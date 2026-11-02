// Shared date/time formatting for the whole console.
// Every clock in the UI uses the operator's local time in 24-hour format,
// so a record never reads differently between pages or drawers.

import { getLanguage } from '../i18n/translator';

export type DateInput = string | number | Date;

/** Calendar dates follow the active console language. */
function dateLocale(): string {
  return getLanguage() === 'id' ? 'id-ID' : 'en-US';
}

const pad = (value: number) => String(value).padStart(2, '0');

function toValidDate(value: DateInput): Date | null {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'number') {
    const fromNumber = new Date(value);
    return Number.isNaN(fromNumber.getTime()) ? null : fromNumber;
  }

  const raw = String(value).trim();
  if (!raw) return null;
  // Stored timestamps are UTC but may carry no zone designator.
  // Treat them as UTC instead of letting the browser parse them as local time.
  const normalized = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw;

  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Local wall-clock time in 24-hour format: 20:17:15 */
export function formatTime(value: DateInput): string {
  const date = toValidDate(value);
  if (!date) return '—';
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** Local wall-clock time without seconds: 20:17 */
export function formatTimeShort(value: DateInput): string {
  const date = toValidDate(value);
  if (!date) return '—';
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Local wall-clock time with milliseconds: 20:17:15.658 */
export function formatTimeWithMs(value: DateInput): string {
  const date = toValidDate(value);
  if (!date) return '—';
  return `${formatTime(date)}.${String(date.getMilliseconds()).padStart(3, '0')}`;
}

/** Local calendar date: Oct 19, 2026 */
export function formatDate(value: DateInput): string {
  const date = toValidDate(value);
  if (!date) return '—';
  return date.toLocaleDateString(dateLocale(), { month: 'short', day: 'numeric', year: 'numeric' });
}

/** Local date and 24-hour time: Oct 19, 2026, 20:17:15 */
export function formatDateTime(value: DateInput): string {
  const date = toValidDate(value);
  if (!date) return '—';
  const datePart = date.toLocaleDateString(dateLocale(), { month: 'short', day: 'numeric', year: 'numeric' });
  return `${datePart}, ${formatTime(date)}`;
}

/**
 * Stored timeline entries written before the 24-hour switch may still hold
 * values such as "8:12:36 PM". Normalize them to "20:12:36" at render time.
 */
export function normalizeClockTime(value: string): string {
  const match = String(value || '').trim().match(/^(\d{1,2})[:.](\d{2})(?:[:.](\d{2}))?\s*([AP]\.?M\.?)?$/i);
  if (!match) return value;
  let hours = Number(match[1]);
  const minutes = match[2];
  const seconds = match[3] ?? '00';
  const meridiem = match[4]?.replace(/\./g, '').toUpperCase();
  if (meridiem === 'PM' && hours < 12) hours += 12;
  if (meridiem === 'AM' && hours === 12) hours = 0;
  return `${pad(hours)}:${minutes}:${seconds}`;
}
