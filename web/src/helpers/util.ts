import { z } from "zod";

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
  const reg = /(^$)|([(\d+)|(\d+.\d+)]\s?[kmg]b)/i;
  return z.string().regex(reg);
}

export function newZodDuration() {
  const reg = /(^$)|(\d+[smhd])/i;
  return z.string().regex(reg);
}

export function formatError(err: Error | HTTPError | unknown): string {
  let message = "";
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

  // Pick characers randomly
  let str = "";
  for (let i = 0; i < length; i++) {
    str += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return str;
}
