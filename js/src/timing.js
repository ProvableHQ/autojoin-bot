// Node clamps larger timer delays to 1 ms.
const MAX_TIMER_DELAY_MS = 2_147_483_647;

export function validateTimerDelay(value, name) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_TIMER_DELAY_MS) {
    throw new Error(`${name} must be an integer between 1 and ${MAX_TIMER_DELAY_MS} milliseconds`);
  }
  return value;
}
