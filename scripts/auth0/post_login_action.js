// Auth0 post-login Action "aegis-claims" (PRD §3.2, §4.3 step 3).
// Copies the user's roles, name and email into the access token under the https://aegis/
// namespace. FastAPI reads roles only from this claim (no role, or only "student", means student).
exports.onExecutePostLogin = async (event, api) => {
  const ns = "https://aegis/";
  const roles = (event.authorization && event.authorization.roles) || [];
  api.accessToken.setCustomClaim(`${ns}roles`, roles);
  api.accessToken.setCustomClaim(`${ns}name`, event.user.name || event.user.nickname || null);
  api.accessToken.setCustomClaim(`${ns}email`, event.user.email || null);
  api.idToken.setCustomClaim(`${ns}roles`, roles);
};
