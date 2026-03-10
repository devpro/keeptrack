import { BackendData } from "./backend-data";

export interface Movie extends BackendData {
  id?: string;
  title?: string;
  year?: number;
  imdbPageId?: string;
  allocineId?: string;
  isEditable?: boolean;
}
