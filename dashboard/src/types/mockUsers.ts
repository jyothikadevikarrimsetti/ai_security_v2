export interface MockUser {
  oid: string;
  display_name: string;
  category: string;
  department: string;
  ad_roles: string[];
  clearance_level: number;
  domain: string;
  bound_policies: string[];
  employment_status: string;
}

export interface MockUsersResponse {
  users: MockUser[];
}

export interface MockTokenResponse {
  jwt_token: string;
  oid: string;
  display_name: string;
  expires_in: number;
}
