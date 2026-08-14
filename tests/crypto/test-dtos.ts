export interface UserMetadata {
  created: string;
  verified: boolean;
}

export interface TestUser {
  id: string;
  name: string | null;
  email: string | null;
  roles: string[] | null;
  metadata: UserMetadata | null;
}

export interface Level2Dto {
  value: string | null;
  items: number[] | null;
}

export interface Level1Dto {
  level2: Level2Dto | null;
}

export interface NestedDto {
  level1: Level1Dto | null;
}

export interface EmptyDto { }