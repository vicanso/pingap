import HTTPError from "./http-error";
export function isError(err: Error | HTTPError | unknown, category: string) {
  if (err instanceof HTTPError) {
    return err.category === category;
  }
  return false;
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
