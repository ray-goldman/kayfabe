function redirect(response, path) { response.redirect(303, path); }
function route(request, response) {
  redirect(response, `/admin/agents?agent=${encodeURIComponent(request.params.id)}`);
}
