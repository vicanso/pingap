import * as React from "react";
import { Plus, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { random } from "@/helpers/util";
import { useI18n } from "@/i18n";

interface CombinedAuth {
  app_id: string;
  ip_list: string[];
  secret: string;
  deviation: number;
}

interface CombinedAuthRow extends CombinedAuth {
  id: string;
  ipText: string;
}

interface CombinedAuthsProps extends Omit<
  React.HTMLAttributes<HTMLDivElement>,
  "defaultValue"
> {
  defaultValue?: CombinedAuth[];
  onValueChange: (values: CombinedAuth[]) => void;
  className?: string;
}

function buildAuthRows(defaultValue: CombinedAuth[]): CombinedAuthRow[] {
  const rows = defaultValue.map((item) => ({
    id: random(),
    app_id: item.app_id || "",
    ip_list: item.ip_list || [],
    ipText: (item.ip_list || []).join(","),
    secret: item.secret || "",
    deviation: item.deviation ?? 10,
  }));
  if (rows.length === 0) {
    rows.push({
      id: random(),
      app_id: "",
      ip_list: [],
      ipText: "",
      secret: "",
      deviation: 10,
    });
  }
  return rows;
}

export const CombinedAuths = React.forwardRef<
  HTMLDivElement,
  CombinedAuthsProps
>(({ defaultValue = [], className, onValueChange, ...props }, ref) => {
  const { t } = useTranslation();
  const pluginI18n = useI18n("plugin");
  const [inputs, setInputs] = React.useState(() => buildAuthRows(defaultValue));

  const commit = (next: CombinedAuthRow[]) => {
    setInputs(next);
    const out: CombinedAuth[] = [];
    next.forEach((item) => {
      if (!item.app_id || !item.secret) {
        return;
      }
      out.push({
        app_id: item.app_id,
        ip_list: item.ip_list,
        secret: item.secret,
        deviation: item.deviation,
      });
    });
    onValueChange(out);
  };

  const updateRow = (
    index: number,
    patch: Partial<Omit<CombinedAuthRow, "id">>,
  ) => {
    const next = inputs.map((row, idx) =>
      idx === index ? { ...row, ...patch } : row,
    );
    commit(next);
  };

  const addRow = () => {
    setInputs((prev) => [
      ...prev,
      {
        id: random(),
        app_id: "",
        ip_list: [],
        ipText: "",
        secret: "",
        deviation: 10,
      },
    ]);
  };

  const removeRow = (index: number) => {
    const next = inputs.filter((_, idx) => idx !== index);
    commit(next);
  };

  return (
    <div className={cn("space-y-3", className)} ref={ref} {...props}>
      {inputs.map((item, index) => (
        <div
          key={item.id}
          className="rounded-lg border border-border bg-background/50 p-4"
        >
          <div className="mb-3 flex items-center justify-between gap-2">
            <span className="figure text-xs font-medium text-muted-foreground">
              {pluginI18n("combinedAuthAuthParameters")} #{index + 1}
            </span>
            {inputs.length > 1 && (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={t("formControls.removeItem")}
                className="size-7 cursor-pointer text-muted-foreground hover:text-destructive"
                onClick={() => removeRow(index)}
              >
                <Trash2 className="size-3.5" />
              </Button>
            )}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">App ID</Label>
              <Input
                className="machine"
                value={item.app_id}
                placeholder={pluginI18n("combinedAuthAuthAppIdPlaceholder")}
                onChange={(e) =>
                  updateRow(index, { app_id: e.target.value.trim() })
                }
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Secret</Label>
              <Input
                className="machine"
                value={item.secret}
                placeholder={pluginI18n("combinedAuthAuthSecretPlaceholder")}
                onChange={(e) =>
                  updateRow(index, { secret: e.target.value.trim() })
                }
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">IP List</Label>
              <Input
                className="machine"
                value={item.ipText}
                placeholder={pluginI18n("combinedAuthAuthIpListPlaceholder")}
                onChange={(e) => {
                  const ipText = e.target.value;
                  const ipList = ipText
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean);
                  updateRow(index, { ipText, ip_list: ipList });
                }}
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">
                Deviation (s)
              </Label>
              <Input
                className="machine"
                type="number"
                value={Number.isFinite(item.deviation) ? item.deviation : ""}
                placeholder={pluginI18n("combinedAuthAuthDeviationPlaceholder")}
                onChange={(e) =>
                  updateRow(index, {
                    deviation: Number(e.target.value.trim() || 0),
                  })
                }
              />
            </div>
          </div>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-8 cursor-pointer gap-1.5 text-xs"
        onClick={addRow}
      >
        <Plus className="size-3.5" />
        {pluginI18n("combinedAuthAuthAdd")}
      </Button>
    </div>
  );
});

CombinedAuths.displayName = "CombinedAuths";
