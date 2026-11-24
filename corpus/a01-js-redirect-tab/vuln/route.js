function redirect(response, path) { response.redirect(303, path); }
function route(request, response) {
  redirect(response, `/	/evil.example/${encodeURIComponent(request.params.id)}`);
}
