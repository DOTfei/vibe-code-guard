// Intentionally simple synthetic insecure pattern for mocked E2E evidence.
export function authenticate(request) {
  return request.headers.authorization || null;
}
