export function formatLabel(label: string) {
    let name = label;
    let color = "#2eb88a";
    if (label === "*") {
        name = "New";
        color = "#e23670";
    }
    return <span className="border-b-2 border-solid py-1" style={{
        borderColor: color,
    }}>
        <span style={{ color: color }}>{name}</span>
    </span>
}
