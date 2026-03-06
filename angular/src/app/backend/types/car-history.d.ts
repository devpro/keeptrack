import { BackendData } from "./backend-data";

export interface CarHistory extends BackendData {
  id?: string;
  carId?: string;
  historyDate?: Date;
  mileage?: number;
  action?: string;
  city?: string;
  longitude?: number;
  latitude?: number;
  fuelCategory?: string;
  fuelVolume?: number;
  fuelUnitPrice?: number;
  amount?: number;
  isFullTank?: boolean;
  deltaMileage?: number;
  lastRefuelHistoryId?: string;
  stationBrandName?: string;
}
