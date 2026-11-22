// Monotonic-anchored local clock (milliseconds since the Unix epoch, sub-ms precision).
// Anchored once to the system wall clock, then advanced only by process.hrtime so later
// system clock steps never disturb offsets measured against it.
const baseWall = Date.now();
const baseHr = process.hrtime.bigint();

export function localMs() {
  return baseWall + Number(process.hrtime.bigint() - baseHr) / 1e6;
}
