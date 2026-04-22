// Created: 2026-03-13 by Constructor Tech
// Updated: 2026-04-22 by Constructor Tech
#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::ty::implements_trait;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::{self as hir, Expr, ExprKind, ImplItemKind, ItemKind, QPath};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{Ty, TypeckResults};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects `.to_string()` calls inside `fn from()` (or `fn try_from()`)
    /// bodies within `impl From<X> for Y` and `impl TryFrom<X> for Y` blocks
    /// where X or Y implements `std::error::Error`, which silently destroys
    /// the error chain. Catches both method-call syntax (`e.to_string()`) and
    /// UFCS form (`ToString::to_string(&e)`), and recurses into closure bodies.
    ///
    /// ### Why is this bad?
    ///
    /// When you call `e.to_string()` inside a `From` impl, you convert the original
    /// error to a string and discard it. The resulting error:
    /// - Has no `.source()` (error chain is broken)
    /// - Cannot be matched or downcast by callers
    /// - Loses structured metadata (error codes, fields, etc.)
    ///
    /// Tools like `anyhow`, `thiserror`'s `#[from]`, or storing the error directly
    /// preserve the chain without any extra effort.
    ///
    /// Unlike the early-pass version, this lint gates on whether the source or target
    /// type actually implements `std::error::Error` (and, for `TryFrom`, also the
    /// associated `Error` type), eliminating false positives from name-based
    /// heuristics. Inside the matched body, `.to_string()` is only flagged when the
    /// receiver type is the source parameter type itself (or the `TryFrom::Error`
    /// assoc type) — `.to_string()` on unrelated error values used for logging is
    /// left alone. Macro-expanded `.to_string()` calls are also ignored.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// // Bad - DatabaseError is swallowed; callers can't inspect the root cause
    /// impl From<DatabaseError> for AppError {
    ///     fn from(e: DatabaseError) -> Self {
    ///         AppError::Internal(e.to_string())  // chain lost!
    ///     }
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// // Good - store the source error; chain preserved
    /// #[derive(thiserror::Error, Debug)]
    /// enum AppError {
    ///     #[error(transparent)]
    ///     Database(#[from] DatabaseError),
    /// }
    /// ```
    pub DE1302_ERROR_FROM_TO_STRING,
    Deny,
    "calling .to_string() in From<XxxError> impl destroys the error chain (DE1302)"
}

/// Returns true if `ty` implements `std::error::Error`.
///
/// Uses the `rustc_diagnostic_item = "Error"` marker and `clippy_utils::ty::implements_trait`
/// for proper trait resolution. Handles ADTs, type aliases, and generic params with bounds.
fn implements_error<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> bool {
    let Some(error_did) = cx.tcx.get_diagnostic_item(rustc_span::sym::Error) else {
        return false;
    };
    implements_trait(cx, ty, error_did, &[])
}

struct ToStringVisitor<'tcx, 'cx> {
    cx: &'cx LateContext<'tcx>,
    /// Typeck results for the body currently being walked. Swapped when we
    /// descend into a closure, which has its own typeck tables.
    typeck: &'tcx TypeckResults<'tcx>,
    /// The source parameter type of the `From` / `TryFrom` impl (`X` in
    /// `impl From<X> for Y`). We only flag `.to_string()` when the receiver
    /// type equals this, which eliminates false positives from stringifying
    /// unrelated error values for logging etc.
    source_ty: Ty<'tcx>,
    /// For `TryFrom` impls, the `type Error = ...` associated type if it
    /// implements `std::error::Error`. Also a valid receiver match — this
    /// catches patterns like stringifying a locally constructed error of the
    /// associated type while building the `Err(..)` branch.
    error_assoc_ty: Option<Ty<'tcx>>,
}

impl<'tcx> ToStringVisitor<'tcx, '_> {
    /// Emit the DE1302 diagnostic at `span`.
    fn emit(&self, span: rustc_span::Span) {
        self.cx.span_lint(DE1302_ERROR_FROM_TO_STRING, span, |diag| {
            diag.primary_message(
                "`.to_string()` in `From` impl destroys the error chain (DE1302)",
            );
            diag.help(
                "store the source error directly, use an enum variant, or use `#[from]` with thiserror",
            );
            diag.note(
                "`.to_string()` discards the original error type: `.source()` returns None and the error cannot be downcast",
            );
        });
    }

    /// Returns true if `ty` (after peeling references) is the source parameter
    /// type of the impl, or the `TryFrom::Error` associated type. This is the
    /// tightened receiver check: only the specific types whose chain would be
    /// destroyed by stringification inside this impl are flagged.
    fn is_relevant_receiver(&self, ty: Ty<'tcx>) -> bool {
        let inner = ty.peel_refs();
        inner == self.source_ty || self.error_assoc_ty.is_some_and(|e| inner == e)
    }
}

impl<'tcx> hir::intravisit::Visitor<'tcx> for ToStringVisitor<'tcx, '_> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // Skip any expression that came from a macro expansion (derive macros,
        // format/tracing macros, `?` desugaring, future format-args lowering).
        // We still descend into children in case the macro wraps user-written
        // subexpressions whose spans are attributed to the caller.
        let in_macro = expr.span.from_expansion();

        match expr.kind {
            // Method call form: `e.to_string()`.
            ExprKind::MethodCall(seg, recv, args, _) if !in_macro => {
                if seg.ident.name.as_str() == "to_string" && args.is_empty() {
                    let recv_ty = self.typeck.expr_ty(recv);
                    if self.is_relevant_receiver(recv_ty) {
                        self.emit(expr.span);
                    }
                }
            }
            // UFCS form: `ToString::to_string(&e)` or `<E as ToString>::to_string(&e)`.
            ExprKind::Call(callee, [arg]) if !in_macro => {
                if is_to_string_path(self.cx, callee) {
                    let arg_ty = self.typeck.expr_ty(arg);
                    if self.is_relevant_receiver(arg_ty) {
                        self.emit(expr.span);
                    }
                }
            }
            // Closures have their own typeck tables. Swap the typeck context so
            // expressions inside `|e| e.to_string()` keep being checked correctly.
            ExprKind::Closure(closure) => {
                let outer_typeck = self.typeck;
                self.typeck = self.cx.tcx.typeck(closure.def_id);
                let body = self.cx.tcx.hir_body(closure.body);
                hir::intravisit::walk_expr(self, body.value);
                self.typeck = outer_typeck;
                return;
            }
            _ => {}
        }
        hir::intravisit::walk_expr(self, expr);
    }
}

/// Returns true if `callee` resolves to `core::string::ToString::to_string`.
/// Handles both `ToString::to_string(&e)` and `<E as ToString>::to_string(&e)` forms.
fn is_to_string_path<'tcx>(cx: &LateContext<'tcx>, callee: &Expr<'tcx>) -> bool {
    let ExprKind::Path(qpath) = &callee.kind else {
        return false;
    };
    let res = match qpath {
        QPath::Resolved(_, path) => path.res,
        QPath::TypeRelative(..) => cx.qpath_res(qpath, callee.hir_id),
        QPath::LangItem(..) => return false,
    };
    let Res::Def(DefKind::AssocFn, def_id) = res else {
        return false;
    };
    let Some(to_string_trait) = cx.tcx.get_diagnostic_item(rustc_span::sym::ToString) else {
        return false;
    };
    // Walk up from the assoc fn to its trait (if any) and compare.
    let Some(trait_did) = cx.tcx.trait_of_assoc(def_id) else {
        return false;
    };
    trait_did == to_string_trait
}

impl<'tcx> LateLintPass<'tcx> for De1302ErrorFromToString {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::Item<'tcx>) {
        let ItemKind::Impl(impl_block) = item.kind else {
            return;
        };

        // Only examine `impl From<X> for Y` and `impl TryFrom<X> for Y` blocks.
        let Some(trait_ref) = impl_block.of_trait else {
            return;
        };
        let Some(last_seg) = trait_ref.trait_ref.path.segments.last() else {
            return;
        };
        let conversion_method = match last_seg.ident.name.as_str() {
            "From" => "from",
            "TryFrom" => "try_from",
            _ => return,
        };

        // Resolve the actual types from the type system.
        // For `impl From<X> for Y`: args[0] = Y (Self), args[1] = X (source type).
        // `TryFrom` shares the same arg layout (the associated `Error` type lives in
        // the impl, not in the trait substs).
        let impl_def_id = item.owner_id.def_id;
        let Some(impl_trait_ref) = cx.tcx.impl_trait_ref(impl_def_id) else {
            return;
        };
        let impl_trait_ref = impl_trait_ref.instantiate_identity();
        let source_ty = impl_trait_ref.args.type_at(1); // X
        let target_ty = impl_trait_ref.args.type_at(0); // Y = Self

        // For `TryFrom`, extract `type Error = ...` — used both to extend the
        // impl-level gate (so bodies that only touch Error via the assoc type
        // still get checked) and to widen the tightened receiver check.
        let error_assoc_ty: Option<Ty<'tcx>> = if conversion_method == "try_from" {
            impl_block.items.iter().find_map(|item_ref| {
                let node = cx.tcx.hir_node_by_def_id(item_ref.owner_id.def_id);
                let hir::Node::ImplItem(impl_item) = node else {
                    return None;
                };
                if impl_item.ident.name.as_str() != "Error" {
                    return None;
                }
                if !matches!(impl_item.kind, ImplItemKind::Type(..)) {
                    return None;
                }
                let ty = cx
                    .tcx
                    .type_of(item_ref.owner_id.def_id)
                    .instantiate_identity();
                implements_error(cx, ty).then_some(ty)
            })
        } else {
            None
        };

        // Gate: at least one of source, target, or (for TryFrom) the Error
        // associated type must actually implement std::error::Error. This
        // replaces name heuristics, eliminating false positives like
        // `impl From<String> for ParseError` where String is not an Error.
        if !implements_error(cx, source_ty)
            && !implements_error(cx, target_ty)
            && error_assoc_ty.is_none()
        {
            return;
        }

        // Walk the `from` / `try_from` body looking for .to_string() calls.
        // tcx.hir() was removed in nightly-2025-09-18; use hir_node_by_def_id instead.
        for item_ref in impl_block.items {
            let node = cx.tcx.hir_node_by_def_id(item_ref.owner_id.def_id);
            let hir::Node::ImplItem(impl_item) = node else {
                continue;
            };
            if impl_item.ident.name.as_str() != conversion_method {
                continue;
            }
            let ImplItemKind::Fn(_, body_id) = impl_item.kind else {
                continue;
            };
            let body = cx.tcx.hir_body(body_id);
            let typeck = cx.tcx.typeck(item_ref.owner_id.def_id);
            let mut visitor = ToStringVisitor {
                cx,
                typeck,
                source_ty,
                error_assoc_ty,
            };
            hir::intravisit::walk_expr(&mut visitor, body.value);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ui_examples() {
        dylint_testing::ui_test_examples(env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn test_comment_annotations_match_stderr() {
        let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui");
        lint_utils::test_comment_annotations_match_stderr(&ui_dir, "DE1302", "to_string");
    }
}
