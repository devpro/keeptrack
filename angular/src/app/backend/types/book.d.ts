import { BackendData } from "./backend-data";

export interface Book extends BackendData {
  id?: string;
  title?: string;
  author?: string;
  series?: string;
  finishedAt?: Date;
  isEditable?: boolean;
}
