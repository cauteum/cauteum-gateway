export * from "./gen/cautem/control/v1/console_pb.js";

import { createClient, type Interceptor, type Transport } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { CatalogService, ConsoleService, OperationsService, PolicyService, ProviderCredentialService, ProviderProfileService, SandboxService } from "./gen/cautem/control/v1/console_pb.js";

export interface ControlClientOptions {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  interceptors?: Interceptor[];
}

export function createControlTransport(options: ControlClientOptions): Transport {
  return createConnectTransport({
    baseUrl: options.baseUrl,
    fetch: options.fetch,
    interceptors: options.interceptors,
    useBinaryFormat: true,
  });
}

export function createControlClients(transport: Transport) {
  return {
    console: createClient(ConsoleService, transport),
    sandboxes: createClient(SandboxService, transport),
    operations: createClient(OperationsService, transport),
    catalog: createClient(CatalogService, transport),
    policy: createClient(PolicyService, transport),
    providerCredentials: createClient(ProviderCredentialService, transport),
    providerProfiles: createClient(ProviderProfileService, transport),
  };
}
