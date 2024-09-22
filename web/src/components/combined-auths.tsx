import * as React from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { random } from "@/helpers/util";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useI18n } from "@/i18n";
import { Button } from "./ui/button";

interface CombinedAuth {
  app_id: string;
  ip_list: string[];
  secret: string;
  deviation: number;
}

interface CombinedAuthsProps {
  defaultValue?: CombinedAuth[];
  onValueChange: (values: CombinedAuth[]) => void;
  className?: string;
}

export const CombinedAuths = React.forwardRef<
  HTMLInputElement,
  CombinedAuthsProps
>(({ defaultValue = [], className, onValueChange, ...props }, ref) => {
  const pluginI18n = useI18n("plugin");
  const arr = defaultValue.map((item) => {
    return {
      id: random(),
      app_id: item.app_id,
      ip_list: item.ip_list,
      secret: item.secret,
      deviation: item.deviation,
    };
  });
  if (arr.length === 0) {
    arr.push({
      id: random(),
      app_id: "",
      ip_list: [],
      secret: "",
      deviation: 10,
    });
  }
  const [inputs, setInputs] = React.useState(arr);
  const setUpdate = (
    values: {
      id: string;
      app_id: string;
      ip_list: string[];
      secret: string;
      deviation: number;
    }[],
  ) => {
    setInputs(values);
    const arr: CombinedAuth[] = [];

    values.forEach((item) => {
      if (!item.app_id || !item.secret) {
        return;
      }
      arr.push({
        app_id: item.app_id,
        ip_list: item.ip_list,
        secret: item.secret,
        deviation: item.deviation,
      });
    });
    onValueChange(arr);
  };

  const items = inputs.map((item, index) => {
    const last = index === inputs.length - 1;
    const mb = last ? "" : "mb-4";
    return (
      <Card key={item.id} className={cn(mb)}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium ">
            {pluginI18n("combinedAuthAuthParameters")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Input
            className="mb-4"
            defaultValue={item.app_id || ""}
            placeholder={pluginI18n("combinedAuthAuthAppIdPlaceholder")}
            onInput={(e) => {
              const value = (e.target as HTMLInputElement).value || "";
              const arr = inputs.slice(0);
              arr[index].app_id = value.trim();
              setUpdate(arr);
            }}
          />
          <Input
            className="mb-4"
            defaultValue={(item.ip_list || []).join(",")}
            placeholder={pluginI18n("combinedAuthAuthIpListPlaceholder")}
            onInput={(e) => {
              const value = (e.target as HTMLInputElement).value || "";
              const arr = inputs.slice(0);
              const ipList: string[] = [];
              value.split(",").forEach((item) => {
                const ip = item.trim();
                if (ip) {
                  ipList.push(ip);
                }
              });
              arr[index].ip_list = ipList;
              setUpdate(arr);
            }}
          />
          <Input
            className="mb-4"
            defaultValue={item.secret || ""}
            placeholder={pluginI18n("combinedAuthAuthSecretPlaceholder")}
            onInput={(e) => {
              const value = (e.target as HTMLInputElement).value || "";
              const arr = inputs.slice(0);
              arr[index].secret = value.trim();
              setUpdate(arr);
            }}
          />
          <Input
            className="mb-4"
            type="number"
            defaultValue={item.deviation}
            placeholder={pluginI18n("combinedAuthAuthDeviationPlaceholder")}
            onInput={(e) => {
              const value = (e.target as HTMLInputElement).value || "";
              const arr = inputs.slice(0);
              arr[index].deviation = Number(value.trim());
              setUpdate(arr);
            }}
          />
          {!last && (
            <Button
              className="w-full"
              onClick={(e) => {
                const arr = inputs.slice(0);
                arr.splice(index, 1);
                setUpdate(arr);
                e.preventDefault();
              }}
            >
              {pluginI18n("combinedAuthAuthRemove")}
            </Button>
          )}
          {last && (
            <Button
              className="w-full"
              onClick={(e) => {
                const arr = inputs.slice(0);
                arr.push({
                  id: random(),
                  app_id: "",
                  ip_list: [],
                  secret: "",
                  deviation: 10,
                });
                setUpdate(arr);
                e.preventDefault();
              }}
            >
              {pluginI18n("combinedAuthAuthAdd")}
            </Button>
          )}
        </CardContent>
      </Card>
    );
  });

  return (
    <div className={cn(className)} ref={ref} {...props}>
      {items}
    </div>
  );
});

CombinedAuths.displayName = "CombinedAuths";
