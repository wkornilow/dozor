import Foundation

/// Adds and removes whole targets in the free text of the targets field.
///
/// Lives beside the validator because it must tokenise text the same way
/// `TargetValidator.parse` does — a second, slightly different split would let
/// the UI claim a target is present when the parser disagrees.
public enum TargetTextEditor {

    public static func tokens(of text: String) -> [String] {
        text.components(separatedBy: TargetValidator.separators)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Whether the exact token is already in the text.
    ///
    /// Deliberately textual, never semantic: `192.168.30.5` being present does
    /// not count as containing `192.168.30.0/24`. A toggle that removed
    /// something the user typed, because it happened to fall inside a range,
    /// would be impossible to predict.
    public static func contains(_ raw: String, in text: String) -> Bool {
        tokens(of: text).contains { $0.caseInsensitiveCompare(raw) == .orderedSame }
    }

    /// Adds the target if absent, removes every occurrence if present.
    ///
    /// The result is normalised — one separator style, no stray commas or
    /// blanks. That happens only on an explicit toggle, never while typing, so
    /// it cannot fight the user's cursor. The separator is taken from what the
    /// text already uses, so a list written one-per-line stays that way.
    public static func toggling(_ raw: String, in text: String) -> String {
        let existing = tokens(of: text)
        let separator: String
        if text.contains("\n") {
            separator = "\n"
        } else if text.contains(",") {
            separator = ", "
        } else {
            separator = " "
        }

        let updated: [String]
        if contains(raw, in: text) {
            updated = existing.filter { $0.caseInsensitiveCompare(raw) != .orderedSame }
        } else {
            updated = existing + [raw]
        }
        return updated.joined(separator: separator)
    }
}
