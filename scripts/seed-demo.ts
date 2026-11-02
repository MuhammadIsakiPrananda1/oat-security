/**
 * Seeds or clears the showcase demo tenant dataset (server/seed/demoSeed.ts).
 *
 *   npm run seed:demo        seed the demo organization and its telemetry
 *   npm run seed:demo:clear  wipe the demo organization's rows
 */
import { clearDemoData, seedDemoData } from '../server/seed/demoSeed';

const clear = process.argv.includes('--clear');

if (clear) {
  clearDemoData();
  console.log('[OAT SECURITY] Demo data cleared for the demo tenant.');
} else {
  const counts = seedDemoData();
  console.log('[OAT SECURITY] Demo data seeded:', counts);
}
