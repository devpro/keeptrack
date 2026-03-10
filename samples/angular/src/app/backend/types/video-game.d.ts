import { BackendData } from "./backend-data";

export interface VideoGame extends BackendData {
  id?: string;
  title?: string;
  platform?: string;
  releasedAt?: Date;
  state?: string;
  finishedAt?: Date;
  isEditable?: boolean;
}
