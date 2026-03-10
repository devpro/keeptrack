import { BackendData } from "./backend-data";

export interface TvShow extends BackendData {
  id?: string;
  title?: string;
  isEditable?: boolean;
}
