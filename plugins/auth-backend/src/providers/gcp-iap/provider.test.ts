/*
 * Copyright 2020 Spotify AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { OAuth2Client } from 'google-auth-library';
import { ConflictError } from '@backstage/errors';
import { parseToken } from './provider';

jest.mock('google-auth-library');

const validJwt =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyIsImlzcyI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.T2BNS4G-6RoiFnXc8Q8TiwdWzTpNitY8jcsGM3N3-Yo';

describe('parseToken', () => {
  it('runs the happy path', async () => {
    const client = {
      getIapPublicKeys: async () => ({ pubkeys: '' }),
      verifySignedJwtWithCertsAsync: async () => ({
        getPayload: () => ({ sub: 's', email: 'e@mail.com' }),
      }),
    };
    await expect(
      parseToken(validJwt, 'a', client as unknown as OAuth2Client),
    ).resolves.toMatchObject({
      iapToken: {
        sub: 's',
        email: 'e@mail.com',
      },
    });
  });

  it('rejects bad tokens', async () => {
    await expect(parseToken(7, 'a', undefined as any)).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'Missing Google IAP header: x-goog-iap-jwt-assertion',
    });
    await expect(
      parseToken(undefined, 'a', undefined as any),
    ).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'Missing Google IAP header: x-goog-iap-jwt-assertion',
    });
    await expect(parseToken('', 'a', undefined as any)).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'Missing Google IAP header: x-goog-iap-jwt-assertion',
    });
  });

  it('translates oauth client errors', async () => {
    const client = {
      getIapPublicKeys: async () => {
        throw new ConflictError('Ouch');
      },
    };
    await expect(
      parseToken(validJwt, 'a', client as unknown as OAuth2Client),
    ).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'Google IAP token verification failed, ConflictError: Ouch',
    });
  });

  it('rejects bad token payloads', async () => {
    const getPayload = jest.fn();
    const client = {
      getIapPublicKeys: async () => ({ pubkeys: '' }),
      verifySignedJwtWithCertsAsync: async () => ({ getPayload }),
    };

    getPayload.mockReturnValueOnce(undefined);
    await expect(
      parseToken(validJwt, 'a', client as unknown as OAuth2Client),
    ).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'Google IAP token had no payload',
    });

    getPayload.mockReturnValueOnce({ sub: 'only' });
    await expect(
      parseToken(validJwt, 'a', client as unknown as OAuth2Client),
    ).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'Google IAP token payload had no sub or email claim',
    });
  });
});

/*
describe('GcpIapProvider', () => {
  const mockRequestWithJwt = {
    header: jest.fn(() => validJwt),
  } as unknown as express.Request;

  const mockRequestWithoutJwt = {
    header: jest.fn(() => undefined),
  } as unknown as express.Request;

  const mockResponse = {
    end: jest.fn(),
    header: () => jest.fn(),
    json: jest.fn().mockReturnThis(),
    status: jest.fn(),
  } as unknown as express.Response;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('runs the happy path', async () => {
    //
  });
});
*/
