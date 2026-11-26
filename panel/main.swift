import AppKit
import SwiftUI

// The request arrives on stdin, never argv, so other local processes cannot
// read it from the process list.
struct Request: Decodable {
    let provider, item, field: String
    let picked: Bool
    let agent, command: String
    let timeout_secs: Double
}

enum Exit: Int32 {
    case denied = 1
    case timedOut = 2
    case badRequest = 3
}

guard let request = try? JSONDecoder().decode(Request.self, from: FileHandle.standardInput.readDataToEndOfFile()),
      request.timeout_secs > 0
else {
    FileHandle.standardError.write(Data("imk-aac-panel: expected one JSON request on stdin\n".utf8))
    exit(Exit.badRequest.rawValue)
}
let provider = request.provider, item = request.item, field = request.field, picked = request.picked
let agent = request.agent, command = request.command
let total = request.timeout_secs
let started = Date()

let lang = Locale.preferredLanguages.first ?? "en"
let strings: [String: [String: String]] = [
    "zh-Hant": ["title": "%@ 想取用一個密碼", "hint": "摸 immurok 放行", "provider": "提供者", "item": "項目",
                "field": "欄位", "picked": "自動選擇", "command": "指令", "deny": "拒絕",
                "left": "%d 秒後自動拒絕", "more": "點一下看完整指令"],
    "en": ["title": "%@ is asking for a secret", "hint": "Touch immurok to allow", "provider": "Provider", "item": "Item",
           "field": "Field", "picked": "Auto-picked", "command": "Command", "deny": "Deny",
           "left": "Denies in %d s", "more": "Click to see the full command"],
]
let table = strings[lang.hasPrefix("zh") ? "zh-Hant" : "en"]!
func t(_ k: String) -> String { table[k]! }

struct Knocking: View {
    @State private var ripple = false
    var body: some View {
        ZStack {
            ForEach(0..<2) { i in
                Circle().stroke(Color.blue.opacity(0.5), lineWidth: 2)
                    .frame(width: 46, height: 46)
                    .scaleEffect(ripple ? 1.7 : 1)
                    .opacity(ripple ? 0 : 0.8)
                    .animation(.easeOut(duration: 1.6).repeatForever(autoreverses: false).delay(Double(i) * 0.8), value: ripple)
            }
            Image(systemName: "person.fill")
                .font(.system(size: 22))
                .foregroundStyle(.white)
                .frame(width: 46, height: 46)
                .background(Circle().fill(LinearGradient(colors: [.blue, .indigo], startPoint: .topLeading, endPoint: .bottomTrailing)))
                .symbolEffect(.breathe)
            Image(systemName: "key.fill")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(.white)
                .padding(5)
                .background(Circle().fill(.orange))
                .offset(x: 17, y: 16)
                .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 1.2)))
        }
        .frame(width: 58, height: 58)
        .onAppear { ripple = true }
    }
}

struct Row: View {
    let label: String
    let value: String
    var badge: String? = nil
    var mono = true
    var body: some View {
        GridRow {
            Text(label).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            HStack(spacing: 6) {
                Text(value).font(.system(size: 13.5, weight: .semibold, design: mono ? .monospaced : .default))
                    .lineLimit(1).truncationMode(.middle)
                if let badge {
                    Text(badge).font(.system(size: 11, weight: .semibold)).foregroundStyle(.white)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Capsule().fill(.orange.opacity(0.85)))
                }
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .gridColumnAlignment(.leading)
        }
    }
}

struct CommandBox: View {
    @State private var expanded = false
    @State private var hovering = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(t("command")).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
                Spacer()
                Image(systemName: expanded ? "chevron.up" : "chevron.down")
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
            }
            Text("$ " + command)
                .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                .lineLimit(expanded || hovering ? nil : 1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if !(expanded || hovering) {
                Text(t("more")).font(.system(size: 10.5)).foregroundStyle(.tertiary)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 16))
        .contentShape(Rectangle())
        .onTapGesture { withAnimation(.spring(duration: 0.3)) { expanded.toggle() } }
        .onHover { h in withAnimation(.easeInOut(duration: 0.2)) { hovering = h } }
        .help(command)
    }
}

struct Countdown: View {
    var body: some View {
        TimelineView(.animation) { ctx in
            let left = max(0, total - ctx.date.timeIntervalSince(started))
            let frac = left / total
            let color: Color = frac > 0.5 ? .blue : (frac > 0.2 ? .orange : .red)
            VStack(alignment: .leading, spacing: 6) {
                GeometryReader { g in
                    ZStack(alignment: .leading) {
                        Capsule().fill(.white.opacity(0.12))
                        Capsule().fill(color.gradient).frame(width: g.size.width * frac)
                    }
                }
                .frame(height: 6)
                Text(String(format: t("left"), Int(left.rounded(.up))))
                    .font(.system(size: 11, weight: .medium).monospacedDigit()).foregroundStyle(.secondary)
            }
        }
    }
}

struct Card: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Knocking()
                VStack(alignment: .leading, spacing: 3) {
                    Text(String(format: t("title"), agent)).font(.system(size: 15, weight: .semibold))
                    Text(t("hint")).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                Button {
                    FileHandle.standardError.write(Data("imk-aac-panel: deny button\n".utf8))
                    exit(Exit.denied.rawValue)
                } label: {
                    Text(t("deny")).font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                        .padding(.horizontal, 16).padding(.vertical, 8)
                        .background(Capsule().fill(Color.red.opacity(0.85)))
                        .glassEffect(.regular.interactive(), in: .capsule)
                }
                .buttonStyle(.plain)
            }
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
                Row(label: t("provider"), value: provider, mono: false)
                Divider().gridCellUnsizedAxes(.horizontal)
                Row(label: t("item"), value: item)
                Divider().gridCellUnsizedAxes(.horizontal)
                Row(label: t("field"), value: field, badge: picked ? t("picked") : nil)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassEffect(.regular, in: .rect(cornerRadius: 16))
            CommandBox()
            Countdown().padding(.horizontal, 4)
        }
        .padding(18)
        .frame(width: 440, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 26))
    }
}

// The window follows the card's height, pinned at the top, so an expanded
// command box is never clipped.
struct Root: View {
    var body: some View {
        Card()
            .fixedSize(horizontal: false, vertical: true)
            .onGeometryChange(for: CGSize.self) { $0.size } action: { fit($0) }
            .frame(maxHeight: .infinity, alignment: .top)
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let size0 = NSHostingView(rootView: Card()).fittingSize
// A click must land on Deny even though this panel never becomes key.
final class FirstMouseHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}
let host = FirstMouseHostingView(rootView: Root())
host.sizingOptions = []
let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: size0.width, height: size0.height),
                    styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
panel.isOpaque = false
panel.backgroundColor = .clear
panel.hasShadow = true
panel.level = .statusBar
panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
panel.contentView = host
let screen = (NSScreen.main ?? NSScreen.screens.first)?.frame ?? .zero

func place(_ size: CGSize) {
    panel.setFrame(NSRect(x: screen.midX - size.width / 2, y: screen.maxY - 190 - size.height,
                          width: size.width, height: size.height), display: true)
    panel.invalidateShadow()
}

var fitGeneration = 0
func fit(_ size: CGSize) {
    fitGeneration += 1
    if size.height >= panel.frame.height {
        place(size)
    } else {
        // Shrink only after the collapse animation, so the content is never cut mid-way.
        let generation = fitGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
            if generation == fitGeneration { place(size) }
        }
    }
}

place(size0)
panel.orderFrontRegardless()
DispatchQueue.main.asyncAfter(deadline: .now() + total) { exit(Exit.timedOut.rawValue) }
app.run()
