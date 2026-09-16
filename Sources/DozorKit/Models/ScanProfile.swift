import Foundation

/// How hard a profile hits the network. Drives the plain-language warning shown
/// before a run and the policy gate in `ScanPolicy`.
public enum ScanIntensity: String, Codable, CaseIterable, Sendable {
    case passive      // host discovery only
    case light        // few ports, polite timing
    case moderate     // default port set
    case heavy        // all ports / version detection
    case aggressive   // -A, scripts, fast timing

    public var order: Int {
        switch self {
        case .passive: return 0
        case .light: return 1
        case .moderate: return 2
        case .heavy: return 3
        case .aggressive: return 4
        }
    }
}

/// Timing template (-T0…-T5) exposed as a named choice rather than a raw flag.
public enum TimingTemplate: Int, Codable, CaseIterable, Sendable {
    case paranoid = 0, sneaky = 1, polite = 2, normal = 3, aggressive = 4, insane = 5

    public var flag: String { "-T\(rawValue)" }
}

public struct ScanProfile: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    /// Short explanation of what the profile does, shown in the picker.
    public var detail: String
    /// Fixed Nmap arguments. Every element is validated against `ArgumentPolicy`
    /// before a run; targets and output flags are appended separately.
    public var arguments: [String]
    public var intensity: ScanIntensity
    public var timing: TimingTemplate
    /// Nmap needs raw sockets for this profile (SYN, UDP, OS detection).
    public var requiresRoot: Bool
    public var isBuiltIn: Bool
    /// Rough seconds-per-host estimate used for the "expected time" hint.
    public var secondsPerHost: Double

    public init(
        id: UUID = UUID(),
        name: String,
        detail: String,
        arguments: [String],
        intensity: ScanIntensity,
        timing: TimingTemplate = .normal,
        requiresRoot: Bool = false,
        isBuiltIn: Bool = false,
        secondsPerHost: Double = 5
    ) {
        self.id = id
        self.name = name
        self.detail = detail
        self.arguments = arguments
        self.intensity = intensity
        self.timing = timing
        self.requiresRoot = requiresRoot
        self.isBuiltIn = isBuiltIn
        self.secondsPerHost = secondsPerHost
    }
}
