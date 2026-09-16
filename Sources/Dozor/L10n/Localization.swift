import Foundation
import DozorKit

public enum AppLanguage: String, CaseIterable, Codable, Sendable {
    case system, ukrainian, english

    var code: String {
        switch self {
        case .ukrainian: return "uk"
        case .english: return "en"
        case .system:
            let preferred = Locale.preferredLanguages.first ?? "en"
            return preferred.hasPrefix("uk") ? "uk" : "en"
        }
    }

    var displayName: String {
        switch self {
        case .system: return L10n.t("lang.system")
        case .ukrainian: return "Українська"
        case .english: return "English"
        }
    }
}

/// Minimal in-code localisation. Keeps the app free of build-time string
/// tooling (no Xcode project), while still resolving at run time so the
/// language can be switched without a restart.
enum L10n {

    nonisolated(unsafe) static var language: AppLanguage = .system

    static var code: String { language.code }

    static func t(_ key: String) -> String {
        let table = code == "uk" ? uk : en
        return table[key] ?? en[key] ?? key
    }

    static func t(_ key: String, _ arguments: CVarArg...) -> String {
        String(format: t(key), arguments: arguments)
    }

    static var reportStrings: ReportStrings {
        code == "uk" ? .ukrainian : .english
    }

    static func intensityName(_ intensity: ScanIntensity) -> String {
        t("intensity.\(intensity.rawValue)")
    }

    static func intensityExplanation(_ intensity: ScanIntensity) -> String {
        t("intensity.\(intensity.rawValue).detail")
    }

    static func timingName(_ timing: TimingTemplate) -> String {
        t("timing.\(timing.rawValue)")
    }

    /// Built-in profiles store keys; custom ones store literal text.
    static func profileName(_ profile: ScanProfile) -> String {
        profile.isBuiltIn ? t(profile.name) : profile.name
    }

    static func profileDetail(_ profile: ScanProfile) -> String {
        profile.isBuiltIn ? t(profile.detail) : profile.detail
    }

    static func duration(_ seconds: Double) -> String {
        if seconds < 60 { return t("time.seconds", Int(seconds.rounded())) }
        if seconds < 3600 {
            return t("time.minutes", Int((seconds / 60).rounded()))
        }
        return t("time.hours", seconds / 3600)
    }
}
