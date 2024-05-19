import { Theme } from "@mui/material/styles";
import * as React from "react";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import Select from "@mui/material/Select";
import OutlinedInput from "@mui/material/OutlinedInput";
import PlaylistRemoveIcon from "@mui/icons-material/PlaylistRemove";
import IconButton from "@mui/material/IconButton";
import AddRoadIcon from "@mui/icons-material/AddRoad";
import Paper from "@mui/material/Paper";

export enum FormItemCategory {
  TEXT = "text",
  NUMBER = "number",
  TEXTAREA = "textarea",
  LOCATION = "location",
  UPSTREAM = "upstream",
  ADDRS = "addrs",
  CHECKBOX = "checkbox",
  HEADERS = "headers",
  PROXY_ADD_HEADERS = "proxyAddHeaders",
  PROXY_SET_HEADERS = "proxySetHeaders",
  WEBHOOK_TYPE = "webhookType",
  WEBHOOK_NOTIFICATIONS = "webhookNotifications",
  PLUGIN = "plugin",
  PLUGIN_STEP = "pluginStep",
  PLUGIN_SELECT = "pluginSelect",
}

export interface CheckBoxItem {
  label: string;
  option: number;
  value: string | number | boolean | null;
}

export interface FormItem {
  id: string;
  label: string;
  defaultValue: unknown;
  span: number;
  category: FormItemCategory;
  minRows?: number;
  options?: string[] | CheckBoxItem[];
  disabled?: boolean;
}

export function getDefaultValues(items: FormItem[]) {
  const data: Record<string, unknown> = {};
  items.forEach((item) => {
    data[item.id] = item.defaultValue;
  });
  return data;
}

export function getStyles(name: string, selectItems: string[], theme: Theme) {
  return {
    fontWeight:
      selectItems.indexOf(name) === -1
        ? theme.typography.fontWeightRegular
        : theme.typography.fontWeightMedium,
  };
}

export function FormSelectField({
  options,
  label,
  value,
  onUpdate,
}: {
  options?: string[] | CheckBoxItem[];
  label: string;
  value: string;
  onUpdate: (data: string) => void;
}) {
  const [newValue, setNewValue] = React.useState(value);

  const opts = options || [];

  return (
    <React.Fragment>
      <InputLabel id={`{item.id}-label`}>{label}</InputLabel>
      <Select
        labelId={`{item.id}-label`}
        id={label}
        value={newValue}
        onChange={(e) => {
          const { value } = e.target;
          setNewValue(value);
          onUpdate(value);
        }}
        input={<OutlinedInput label={label} />}
      >
        {opts.map((name) => {
          if (typeof name == "string") {
            return (
              <MenuItem key={name} value={name}>
                {name}
              </MenuItem>
            );
          }
          let opt = name as CheckBoxItem;
          return (
            <MenuItem key={opt.label} value={opt.value as string}>
              {opt.label}
            </MenuItem>
          );
        })}
      </Select>
    </React.Fragment>
  );
}

export function FormTwoInputFields({
  id,
  divide,
  values,
  label,
  valueLabel,
  valueWidth,
  addLabel,
  onUpdate,
}: {
  id: string;
  divide: string;
  values: string[];
  label: string;
  valueWidth?: string;
  valueLabel: string;
  addLabel: string;
  onUpdate: (data: string[]) => void;
}) {
  const arr = values || [];
  if (arr.length === 0) {
    arr.push("");
  }
  const isSingleMode = divide == "";
  const [newValues, setNewValues] = React.useState(arr);
  const divideToTwoValues = (value: string) => {
    if (isSingleMode) {
      return [value];
    }
    let arr = value.split(divide);
    if (arr.length < 2) {
      arr.push("");
    }
    if (arr.length > 2) {
      arr = [arr[0], arr.slice(1).join(divide)];
    }
    return arr;
  };
  const updateNameAndValue = (
    index: number,
    name: string | undefined,
    value: string | undefined,
  ) => {
    const cloneValues = newValues.slice(0);
    const arr = divideToTwoValues(cloneValues[index]);
    if (isSingleMode) {
      cloneValues[index] = name || "";
    } else {
      if (name === undefined) {
        arr[1] = value || "";
      } else {
        arr[0] = name;
      }
      cloneValues[index] = arr.join(divide).trim();
    }
    setNewValues(cloneValues);
    const updateValues: string[] = [];
    cloneValues.forEach((item) => {
      const v = item.trim();
      if (v) {
        updateValues.push(v);
      }
    });
    onUpdate(updateValues);
  };

  const list = newValues.map((item, index) => {
    const arr = divideToTwoValues(item);
    const name = arr[0];
    let value = "";
    if (arr.length === 2) {
      value = arr[1];
    }
    let flexValue: number | undefined = undefined;
    if (!valueWidth) {
      flexValue = 1;
    }
    let valueDom = <></>;
    if (!isSingleMode) {
      valueDom = (
        <TextField
          id={`${id}-${index}value`}
          label={valueLabel}
          variant="outlined"
          defaultValue={value || ""}
          sx={{ ml: flexValue, flex: flexValue }}
          style={{
            marginLeft: "10px",
            width: valueWidth,
          }}
          onChange={(e) => {
            const value = e.target.value.trim();
            updateNameAndValue(index, undefined, value);
          }}
        />
      );
    }
    return (
      <Paper
        key={`{id}-${index}`}
        sx={{
          display: "flex",
          marginBottom: "15px",
          alignItems: "center",
          width: "100%",
        }}
      >
        <TextField
          id={`${id}-${index}-name`}
          label={label}
          variant="outlined"
          defaultValue={name || ""}
          sx={{ ml: 1, flex: 1 }}
          style={{
            marginLeft: "0px",
          }}
          onChange={(e) => {
            const value = e.target.value.trim();
            updateNameAndValue(index, value, undefined);
          }}
        />
        {valueDom}
        <IconButton
          color="primary"
          sx={{ p: "10px" }}
          aria-label="directions"
          onClick={() => {
            const values = newValues.slice(0);
            values.splice(index, 1);
            setNewValues(values);
            onUpdate(values);
          }}
        >
          <PlaylistRemoveIcon />
        </IconButton>
      </Paper>
    );
  });
  list.push(
    <Button
      key="addAddr"
      variant="contained"
      endIcon={<AddRoadIcon />}
      onClick={() => {
        const values = newValues.slice(0);
        values.push("");
        setNewValues(values);
      }}
    >
      {addLabel}
    </Button>,
  );
  return <React.Fragment>{list}</React.Fragment>;
}
