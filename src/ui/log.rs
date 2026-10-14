//! Log page: read-only multiline text area over the backend event log
//! (plain text widgets are NOT selectable; the input gives mouse-
//! selection + Ctrl-C for free). A "Copy log" button puts the whole
//! buffer, oldest first, straight on the clipboard.

use gpui::{ClipboardItem, Context, Entity, ParentElement, Styled, Window};
use gpuikit::elements::button::button;
use gpuikit::elements::input::text_area;
use gpuikit::elements::typography::{h3, small};
use gpuikit::layout::{h_stack, v_stack};

use crate::ui::app::AppRoot;

pub fn render(
    app: &mut AppRoot,
    view: &Entity<AppRoot>,
    _window: &mut Window,
    cx: &mut Context<AppRoot>,
) -> gpui::Div {
    // Sync the read-only view with the log buffer, oldest first.
    let joined = app
        .state
        .log
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    if app.log_input.read(cx).content() != joined {
        app.log_input
            .update(cx, |input, cx| input.set_content_silent(joined, cx));
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
                .child(small(format!(
                    "{} lines — click, drag, Ctrl-A/Ctrl-C to copy",
                    app.state.log.len()
                )))
                .child(gpui::div().flex_1())
                .child(button("btn-copy-log", "Copy log").on_click({
                    let view = view.clone();
                    move |_, _window, cx| {
                        let joined = view
                            .read(cx)
                            .state
                            .log
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("\n");
                        cx.write_to_clipboard(ClipboardItem::new_string(joined));
                        view.update(cx, |app, cx| {
                            app.state.push_log("log copied to clipboard");
                            cx.notify();
                        });
                    }
                })),
        )
        .child(gpui::div().flex_1().min_h_0().child(text_area(&app.log_input, cx)))
}
