const counters = new Map<string, number>();

export function incrementMetric(name: string, amount = 1): void {
  counters.set(name, (counters.get(name) || 0) + amount);
}

export function renderPrometheusMetrics(): string {
  const lines: string[] = [];
  for (const [name, value] of Array.from(counters.entries()).sort()) {
    lines.push(`# TYPE ${name} counter`);
    lines.push(`${name} ${value}`);
  }
  return `${lines.join('\n')}\n`;
}
