---
id: provider
title: Google Identity-Aware Proxy Provider
sidebar_label: Google IAP
# prettier-ignore
description: Adding Google Identity-Aware Proxy as an authentication provider in Backstage
---

# Using Google Identity-Aware Proxy to authenticate requests

Backstage allows offloading the responsibility of authenticating users to the
Google HTTPS Load Balancer & [IAP](https://cloud.google.com/iap), leveraging the
authentication support on the latter.

This tutorial shows how to use authentication on an IAP sitting in front of
Backstage.

It is assumed an IAP is already serving traffic in front of a Backstage instance
configured to serve the frontend app from the backend.

## Frontend Changes

The Backstage app needs a `SignInPage` to be configured. When using IAP Proxy
authentication Backstage will only be loaded once the user has successfully
authenticated; we won't need to display a sign-in page as such, however we will
need to create a dummy `SignInPage` component that can decode and refresh the
token.

- edit `packages/app/src/App.tsx`
- import the following two additional definitions from
  `@backstage/core-plugin-api`: `useApi`, `configApiRef`; these will be used to
  check whether Backstage is running locally or behind IAP
- add the following definition just before the app is created
  (`const app = createApp`):

```ts
const refreshToken = async ({ props, discoveryApiConfig, config }) => {
  const baseUrl = await discoveryApiConfig.getBaseUrl('auth');
  const shouldAuth = config.has('auth.providers.gcp-iap');

  if (!shouldAuth) {
    props.onResult({
      userId: 'guest',
      profile: {
        email: 'guest@example.com',
        displayName: 'Guest',
        picture: '',
      },
    });
    return;
  }

  try {
    const request = await fetch(`${baseUrl}/gcp-iap/refresh`, {
      headers: {
        'x-requested-with': 'XMLHttpRequest',
      },
      credentials: 'include',
    });
    const data = await request.json();

    props.onResult({
      userId: data.backstageIdentity.id ?? 'nouser@ms.at',
      profile: data.profile ?? 'nouser@ms.at',
    });
  } catch (e) {
    props.onResult({
      userId: 'guest',
      profile: {
        email: 'guest@example.com',
        displayName: 'Guest',
        picture: '',
      },
    });
  }
};

const DummySignInComponent: any = (props: any) => {
  try {
    const config = useApi(configApiRef);
    const discoveryApiConfig = useApi(discoveryApiRef);
    refreshToken({ props, discoveryApiConfig, config });
    return <div />;
  } catch (err) {
    return <div>{err.message}</div>;
  }
};
```

## Backend Changes

- Add a `providerFactories` entry to the router in
  `packages/backend/plugin/auth.ts`.

```ts
import { createGcpIAPProvider } from '@backstage/plugin-auth-backend';

export default async function createPlugin({
  logger,
  database,
  config,
  discovery,
}: PluginEnvironment): Promise<Router> {
  return await createRouter({
    logger,
    config,
    database,
    discovery,
    providerFactories: {
      'gcp-iap': createGcpIapProvider({
        // Replace the auth handler if you want to customize the returned user
        // profile info (can be lef out; default implementation shown below
        // which only returns the email.
        async authHandler({ iapToken }) {
          return { profile: { email: iapToken.email } };
        },
        // You need to supply an identity resolver, that takes the profile and
        // the IAP token and produces the Backstage token with the relevant
        // user info.
        async identityResolver({ profile, result: { iapToken } }, ctx) {
          // Somehow compute the Backstage token claims, just some dummy code
          // shown here, but you may want to query your LDAP server, or GSuite
          // or similar, based on the IAP token sub/email claims
          const id = `user:default/${iapToken.email.split('@')[0]}`;
          const fullEnt = ['group:default/team-name'];
          const token = await ctx.tokenIssuer.issueToken({
            claims: { sub: id, ent: fullEnt },
          });
          return { id, token };
        }
      },
    },
  });
}
```

## Configuration

Use the following `auth` configuration:

```yaml
auth:
  providers:
    gcp-iap:
      audience:
        '/projects/<project number>/global/backendServices/<backend service id>'
```
