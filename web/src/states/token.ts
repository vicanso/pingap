import { sha256 } from "@/helpers/util";

const PINGAP_LOGIN_TOKEN = "pingap:loginToken";

export async function saveLoginToken(account: string, password: string) {
  const now = Math.floor(Date.now() / 1000);
  const token = await sha256(`${account}:${password}:${now}`);
  window.localStorage.setItem(PINGAP_LOGIN_TOKEN, `${token}:${now}`);
}

export function getLoginToken() {
  return window.localStorage.getItem(PINGAP_LOGIN_TOKEN) || "";
}

export function removeLoginToken() {
  window.localStorage.removeItem(PINGAP_LOGIN_TOKEN);
}
