import { ArmObj } from "projects/app-service-diagnostics/src/app/shared/models/armObj";

export interface ApiManagementServiceResource extends ArmObj {
    etag: string;
    zones: string[];
    properties: {
        additionalLocations: AdditionalLocation[];
        developerPortalUrl: string;
        disableGateway: boolean;
        gatewayUrl: string;
        // hostnamesCOnfigurations: 
        managementApiUrl: string;


        portalUrl: string;
        privateIPAddresses?: string[];
        platformVersion: PlatformVersion;

        publicIPAddresses?: string[];
        publicIPAddressId?: string;

        virtualNetworkConfiguration?: VirtualNetworkConfiguration;
        virtualNetworkType: VirtualNetworkType;
    }
}

interface VirtualNetworkConfiguration {
    subnetResourceId: string;
    subnetname: string;
    vnetid: string;
}

export enum VirtualNetworkType {
    EXTERNAL = "External",
    INTERNAL = "Internal",
    NONE = "None"
}

export enum PlatformVersion {
    STV1 = "stv1",
    STV2 = "stv2"
}

interface AdditionalLocation {
    disableGateway: boolean;
    gatewayRegionalUrl: string;
    location: string;
    // platformVersion: 
    privateIPAddresses: string[];
    publicIPAddresses: string[];
    publicIpAddressId: string;
    zones: string[];
}