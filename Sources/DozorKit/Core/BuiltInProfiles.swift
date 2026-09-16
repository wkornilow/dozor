import Foundation

/// Built-in profiles. `name` and `detail` hold localisation keys; the UI layer
/// resolves them. Custom profiles carry literal text instead.
public enum BuiltInProfiles {

    public static let all: [ScanProfile] = [discovery, quick, standard, service, fullTCP, udpTop, aggressive]

    public static let discovery = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        name: "profile.discovery.name",
        detail: "profile.discovery.detail",
        arguments: ["-sn", "-n"],
        intensity: .passive,
        timing: .normal,
        isBuiltIn: true,
        secondsPerHost: 0.15
    )

    public static let quick = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
        name: "profile.quick.name",
        detail: "profile.quick.detail",
        arguments: ["-sT", "--top-ports", "100", "--open", "--reason"],
        intensity: .light,
        timing: .aggressive,
        isBuiltIn: true,
        secondsPerHost: 2
    )

    public static let standard = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
        name: "profile.standard.name",
        detail: "profile.standard.detail",
        arguments: ["-sT", "--top-ports", "1000", "--reason"],
        intensity: .moderate,
        timing: .normal,
        isBuiltIn: true,
        secondsPerHost: 5
    )

    public static let service = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000004")!,
        name: "profile.service.name",
        detail: "profile.service.detail",
        arguments: ["-sT", "-sV", "--version-intensity", "5", "--top-ports", "1000", "--reason"],
        intensity: .moderate,
        timing: .normal,
        isBuiltIn: true,
        secondsPerHost: 30
    )

    public static let fullTCP = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000005")!,
        name: "profile.fullTCP.name",
        detail: "profile.fullTCP.detail",
        arguments: ["-sT", "-p", "1-65535", "--reason"],
        intensity: .heavy,
        timing: .aggressive,
        isBuiltIn: true,
        secondsPerHost: 30
    )

    public static let udpTop = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000006")!,
        name: "profile.udpTop.name",
        detail: "profile.udpTop.detail",
        arguments: ["-sU", "--top-ports", "50", "--reason"],
        intensity: .heavy,
        timing: .normal,
        requiresRoot: true,
        isBuiltIn: true,
        secondsPerHost: 120
    )

    public static let aggressive = ScanProfile(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000007")!,
        name: "profile.aggressive.name",
        detail: "profile.aggressive.detail",
        arguments: ["-sT", "-sV", "-sC", "--top-ports", "1000", "--reason"],
        intensity: .aggressive,
        timing: .aggressive,
        isBuiltIn: true,
        secondsPerHost: 60
    )
}
