class HTTPError extends Error {
  // error message
  message: string;
  status?: number;
  exception?: boolean;
  category?: string;
  constructor(message: string) {
    super(message);
    this.message = message;
  }
}

export default HTTPError;
