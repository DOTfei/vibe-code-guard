export function getUser(request) {
  return { id: request.params.id, synthetic: true };
}
