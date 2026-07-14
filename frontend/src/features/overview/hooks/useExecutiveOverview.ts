import { useQuery } from "@tanstack/react-query";

import { fetchApi } from "@/lib/api";
import type { ExecutiveOverviewResponse } from "@/lib/types";

export function useExecutiveOverview() {
  return useQuery({
    queryKey: ["overview", "executive"],
    queryFn: () =>
      fetchApi<ExecutiveOverviewResponse>("/api/overview/executive"),
    refetchInterval: 60_000,
  });
}
