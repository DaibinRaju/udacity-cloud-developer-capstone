import { CustomAuthorizerEvent, CustomAuthorizerResult } from "aws-lambda";
import "source-map-support/register";

import { verify, decode } from "jsonwebtoken";
import { createLogger } from "../../utils/logger";
// import Axios from "axios";
import { JwtPayload } from "../../auth/JwtPayload";
import { Jwt } from "../../auth/Jwt";
const logger = createLogger("auth");

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = "https://dev-ffr9sby7.us.auth0.com/.well-known/jwks.json";

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info("Authorizing a user", event.authorizationToken);
  
  try {
    const jwtToken = await verifyToken(event.authorizationToken);
    logger.info("User was authorized", jwtToken);

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Allow",
            Resource: "*",
          },
        ],
      },
    };
  } catch (e) {
    logger.error("User not authorized", { error: e.message });

    return {
      principalId: "user",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Deny",
            Resource: "*",
          },
        ],
      },
    };
  }
};

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  const token = getToken(authHeader);

  const jwt: Jwt = decode(token, { complete: true }) as Jwt;
  const jwtKid = jwt.header.kid;

  const jwks={"keys":[{"alg":"RS256","kty":"RSA","use":"sig","n":"wlsSjwpkgWCMN9un83_u0l-bzickjM7B41NOQMrZy8U8F7BmE-KO-yP1kdMDF0QQkjOBPF4spgNkwGwtxom6_D7ib3bLZXmKJiY0xbnk0Kin9Aakjd4D_QLpvhTm-ELibCa5XOS0wiit_wE4qTfoEPQHGbgFsemErQJVOMJanRdPRqjC2E07NAUG3fcK0200mIQrduanEb_FUHIYpk2TT97ZkFYtvl2FMsi0twp4a_oHUnvccBRLlNKW4tPGYvVgLvgXD2DbvYEvBXZCmZc09Y3z572kaApOswY5x20YCxnyr1NdZOyObXowyFkPeCwC1lZxgLAFgOOOi3Lnef9wlQ","e":"AQAB","kid":"ULWF7WRytVfu6W0dC_zOx","x5t":"ipu_PeBllNPvauxVMUT9rnWuCfk","x5c":["MIIDDTCCAfWgAwIBAgIJFN4RB5l+ByFyMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1mZnI5c2J5Ny51cy5hdXRoMC5jb20wHhcNMjEwOTEwMDMzNzM2WhcNMzUwNTIwMDMzNzM2WjAkMSIwIAYDVQQDExlkZXYtZmZyOXNieTcudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlsSjwpkgWCMN9un83/u0l+bzickjM7B41NOQMrZy8U8F7BmE+KO+yP1kdMDF0QQkjOBPF4spgNkwGwtxom6/D7ib3bLZXmKJiY0xbnk0Kin9Aakjd4D/QLpvhTm+ELibCa5XOS0wiit/wE4qTfoEPQHGbgFsemErQJVOMJanRdPRqjC2E07NAUG3fcK0200mIQrduanEb/FUHIYpk2TT97ZkFYtvl2FMsi0twp4a/oHUnvccBRLlNKW4tPGYvVgLvgXD2DbvYEvBXZCmZc09Y3z572kaApOswY5x20YCxnyr1NdZOyObXowyFkPeCwC1lZxgLAFgOOOi3Lnef9wlQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQmz1+5wqwd1X7SMx6OU2nG+KYcIDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBABnOMRUf+efkYOfPGU4Ra7MDiFf/TOPjjKXb0OU8zIdfwecx9GBASLb0s1OOJqctt91eGlv4CvEW8WaCdyBECxeINPL7b1OGeQA/f15pkewxu0NhkctR/LykyDUq3skPVtJjoer01w2r4JwWVDBZS2xzdchqyaAUlqzHFYpP6kOkf84d7Hj6goVbDdaOX05ubZ+gAg4befpoKPQ3iaxOCHrMeVF1hASGlTRYCGhp/2pL85GBcdYR+8RBGV82Je4bSR1GGtrmzJqQl0XxLtg6KckEQEgvf1W+GOy+XzfQYEQASA/5Rg9DxGelAYkLJraHUDENsoXr2Q+AuTpLqFQpYVo="]},{"alg":"RS256","kty":"RSA","use":"sig","n":"npLVKy0JtuzKdsEDuo02225FB_20n3pr9Gz2qp3pr7T3jH2tp3nbEcG7Ccv_4mLhtfyvG8AxpZxIbhkR6NVs37JZYFh8iPJCKqmbmFLvemJNEEw5UYpmDzaRe4pW5gBsPVL-v7VfeylF27josJcWcV5ax4FRk75NSCoyXarI5846f9ilLo4JF_yZ-JPATXvsPB2p5GIMBWq9e3sgV6dVLJ7Tj3GO1NtnZ3sFb52p6vvORX7vGy1HQINjpW3lz5eS1izO85wuzZbLiHiMc0G1WiggwfbuOuF-mvNbun04N5TuuXIuW8nspNG8w9RsLlwtHxUjkAh61eYCM9ZwEhjctQ","e":"AQAB","kid":"hpS4FGNkHQTPcsb5qLW5t","x5t":"ooAEvrxYDDNNCzk_gt6x9XSZY80","x5c":["MIIDDTCCAfWgAwIBAgIJDBnFfHrakCdYMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1mZnI5c2J5Ny51cy5hdXRoMC5jb20wHhcNMjEwOTEwMDMzNzM2WhcNMzUwNTIwMDMzNzM2WjAkMSIwIAYDVQQDExlkZXYtZmZyOXNieTcudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnpLVKy0JtuzKdsEDuo02225FB/20n3pr9Gz2qp3pr7T3jH2tp3nbEcG7Ccv/4mLhtfyvG8AxpZxIbhkR6NVs37JZYFh8iPJCKqmbmFLvemJNEEw5UYpmDzaRe4pW5gBsPVL+v7VfeylF27josJcWcV5ax4FRk75NSCoyXarI5846f9ilLo4JF/yZ+JPATXvsPB2p5GIMBWq9e3sgV6dVLJ7Tj3GO1NtnZ3sFb52p6vvORX7vGy1HQINjpW3lz5eS1izO85wuzZbLiHiMc0G1WiggwfbuOuF+mvNbun04N5TuuXIuW8nspNG8w9RsLlwtHxUjkAh61eYCM9ZwEhjctQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQipUf71izb+tR7OP5qEILvDb8MYjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBADU4c6h0VtjbxCYaWFtNzp2hwa1OeS02hxK8oIacd38I4faGcp/13eAFhyWKEHwu6eVXv90MvBEm8cdzG/6aT6EjjuKIlWVDHBmS8a4tezE4cPC05VgXzZklTeEA/9Hmzpqk9pMFb9gczfYMD0IoY0XspKtN4wIPtpbX2AVVlWtXsgNLKa51j0hUymWZcucoxMoPRCtNxbKJXBbYGXBIZ9QUyzjgDlfb7I4bXaA6qLjamfoNULW3zC6WBHIYMKlQdNtQRI0998w8kmSj18jyfb1AZIU/SbQaq7dZH2W3VTA2bKr/bun96LOJs1jZPN1kZXYkofPceSq0zf4nn587100="]}]}
  // const jwks = await Axios.get(jwksUrl);
  // const jwks = await Axios.get(jwksUrl);


  const signingKey = jwks.keys.filter((k) => k.kid === jwtKid)[0];

  if (!signingKey) {
    throw new Error(`Unable to find a signing key that matches '${jwtKid}'`);
  }

  const { x5c } = signingKey;

  const cert = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
  if (!jwt) {
    throw new Error("invalid token");
  }
  return verify(token, cert, { algorithms: ["RS256"] }) as JwtPayload;
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error("No authentication header");

  if (!authHeader.toLowerCase().startsWith("bearer "))
    throw new Error("Invalid authentication header");

  const split = authHeader.split(" ");
  const token = split[1];

  return token;
}
