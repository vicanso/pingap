import { z } from "zod";
import sha256hash from "crypto-js/sha256";
import hex from "crypto-js/enc-hex";
import { isString } from "radash";

import HTTPError from "./http-error";
export function isError(err: Error | HTTPError | unknown, category: string) {
  if (err instanceof HTTPError) {
    return err.category === category;
  }
  return false;
}

export function newZodNumber() {
  const reg = /(^$)|(\d+)/i;
  return z.string().regex(reg);
}

export function newZodBytes() {
  const reg = /(^$)|([(\d+)|(\d+.\d+)]\s?[kmg]i?b)/i;
  return z.string().regex(reg);
}

export function newZodDuration() {
  const reg = /(^$)|(\d+[smhd])/i;
  return z.string().regex(reg);
}

export function omitEmptyArrayString(data: Record<string, unknown>) {
  Object.keys(data).forEach((key) => {
    const value = data[key];
    if (Array.isArray(value) && (value as []).length === 0) {
      delete data[key];
    }
    if (isString(value) && !value) {
      delete data[key];
    }
  });
}

export function formatError(err: Error | HTTPError | unknown): string {
  let message: string;
  if (err instanceof HTTPError) {
    message = err.message;
    if (err.category) {
      message += ` [${err.category.toUpperCase()}]`;
    }
    // 如果是异常（客户端异常，如请求超时，中断等），则上报user action
    if (err.exception) {
      // const currentLocation = getCurrentLocation();
      // actionAdd({
      //   category: ERROR,
      //   route: currentLocation.name,
      //   path: currentLocation.path,
      //   result: FAIL,
      //   message,
      // });
    }
  } else if (err instanceof Error) {
    message = err.message;
  } else {
    message = (err as Error).message;
  }
  return message;
}

export function random(length = 8) {
  // Declare all characters
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  // Pick characters randomly
  let str = "";
  for (let i = 0; i < length; i++) {
    str += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return str;
}

/**
 * Seconds since `startTime` as a two-unit duration: `3d 07h`, `7h 12m`, `48s`.
 * Two units is the readable limit at a glance, and the console shows uptime in
 * places where it is a status, not a measurement.
 */
export function formatUptime(startTime?: number | null) {
  if (!startTime) {
    return "";
  }
  const total = Math.max(0, Math.floor(Date.now() / 1000) - startTime);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const pad = (n: number) => n.toString().padStart(2, "0");
  if (days > 0) {
    return `${days}d ${pad(hours)}h`;
  }
  if (hours > 0) {
    return `${hours}h ${pad(minutes)}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${pad(seconds)}s`;
  }
  return `${seconds}s`;
}

/** Whole days from now until `at` (unix seconds); negative once it has passed. */
export function daysUntil(at: number) {
  return Math.floor((at - Date.now() / 1000) / 86400);
}

export async function sha256(message: string) {
  const hashDigest = sha256hash(message);
  return hex.stringify(hashDigest);
}
