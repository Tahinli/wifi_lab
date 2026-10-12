//! Log page: scrolling monospace view of the backend event log, newest
//! entries first.

use gpui::{Context, Entity, ParentElement, Styled, Window};
use gpuikit::elements::scroll_area::scroll_area;
use gpuikit::elements::typography::{h3, small, text};
use gpuikit::layout::{h_stack, v_stack};
use gpuikit::theme::{ActiveTheme, Themeable};

use crate::ui::app::AppRoot;

pub fn render(
    app: &mut AppRoot,
    _view: &Entity<AppRoot>,
    _window: &mut Window,
    cx: &mut Context<AppRoot>,
) -> gpui::Div {
    let theme = cx.theme().clone();

    let mut lines_view = v_stack().gap_0p5();
    if app.state.log.is_empty() {
        lines_view = lines_view.child(small("log is empty"));
    } else {
        for line in app.state.log.iter().rev() {
            lines_view = lines_view.child(text(line.clone()).code().small());
        }
    }

    v_stack()
        .size_full()
        .gap_2()
        .p_4()
        .child(
            h_stack()
                .items_center()
                .gap_3()
                .child(h3("Log"))
                .child(small(format!("{} lines (newest first)", app.state.log.len()))),
        )
        .child(
            scroll_area("log-scroll")
                .vertical()
                .full_height(true)
                .child(
                    lines_view
                        .w_full()
                        .p_2()
                        .rounded_md()
                        .bg(theme.surface_secondary()),
                ),
        )
}
