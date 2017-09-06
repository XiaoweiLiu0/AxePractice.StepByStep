using System;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;

namespace SessionModuleClient
{
    public class AuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple { get; } = false;

        public bool RedirectToLoginOnChallenge { get; set; }

        public async Task AuthenticateAsync(
            HttpAuthenticationContext context,
            CancellationToken cancellationToken)
        {
            #region Please implement the following method

            /*
             * We need to create IPrincipal from the authentication token. If
             * we can retrive user session, then the structure of the IPrincipal
             * should be in the following form:
             * 
             * ClaimsPrincipal
             *   |- ClaimsIdentity (Primary)
             *        |- Claim: { key: "token", value: "$token value$" }
             *        |- Claim: { key: "userFullName", value: "$user full name$" }
             *
             * If user session cannot be retrived, then the context principal
             * should be an empty ClaimsPrincipal (unauthenticated).
             */
            if (context == null) { return; }
            HttpRequestMessage request = context.Request;
            string token = GetSessionToken(request);
            if (token == null)
            {
                SetAnonymousPrincipal(context);
                return;
            }

            UserSessionDto session = await GetSession(
                context,
                cancellationToken,
                token);
            if (session == null)
            {
                SetAnonymousPrincipal(context);
                return;
            }

            SetAuthenticatedPrincipal(context, token, session);
        }

        static void SetAnonymousPrincipal(HttpAuthenticationContext context)
        {
            context.Principal = new ClaimsPrincipal();
        }

        static void SetAuthenticatedPrincipal(HttpAuthenticationContext context, string token, UserSessionDto session)
        {
            context.Principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim("token", token),
                        new Claim("userFullName", session.UserFullname),
                    },
                    "custom_authentication"));
        }

        public Task ChallengeAsync(
            HttpAuthenticationChallengeContext context,
            CancellationToken cancellationToken)
        {
            /*
             * The challenge method will try checking the configuration of
             * RedirectToLoginOnChallenge property. If the value is true,
             * then it will replace the response to redirect to login page.
             * And if the value is false, then simply keeps the original
             * response.
             */
            if (RedirectToLoginOnChallenge)
            {
                context.Result = new RedirectToLoginPageIfUnauthorizedResult(
                    context.Request, context.Result);
            }
        }
    }
}