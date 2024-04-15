import * as React from "react";
import CardContent from "@mui/material/CardContent";
import Button from "@mui/material/Button";
import Typography from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import FormControl from "@mui/material/FormControl";
import Grid from "@mui/material/Grid";
import FormControlLabel from "@mui/material/FormControlLabel";
import Checkbox from "@mui/material/Checkbox";
import RadioGroup from "@mui/material/RadioGroup";
import Radio from "@mui/material/Radio";
import Snackbar from "@mui/material/Snackbar";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import Select from "@mui/material/Select";
import OutlinedInput from "@mui/material/OutlinedInput";
import PlaylistRemoveIcon from "@mui/icons-material/PlaylistRemove";
import IconButton from "@mui/material/IconButton";
import AddRoadIcon from "@mui/icons-material/AddRoad";
import Alert from "@mui/material/Alert";
import CheckIcon from "@mui/icons-material/Check";
import FormGroup from "@mui/material/FormGroup";
import FormLabel from "@mui/material/FormLabel";
import Stack from "@mui/material/Stack";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemText from "@mui/material/ListItemText";
import Box from "@mui/material/Box";

import Paper from "@mui/material/Paper";
import { Theme, useTheme } from "@mui/material/styles";
import { formatError } from "../helpers/util";

export enum FormItemCategory {
  TEXT = "text",
  NUMBER = "number",
  TEXTAREA = "textarea",
  LOCATION = "location",
  UPSTREAM = "upstream",
  ADDRS = "addrs",
  CHECKBOX = "checkbox",
  HEADERS = "headers",
  PROXY_HEADERS = "proxyHeaders",
  WEBHOOK_TYPE = "webhookType",
  PROXY_PLUGIN = "proxyPlugin",
  PROXY_PLUGIN_SELECT = "proxyPluginSelect",
}

export enum ProxyPluginCategory {
  STATS = "Stats",
  LIMIT = "Limit",
  COMPRESSION = "Compression",
  ADMIN = "Admin",
  DIRECTORY = "Directory",
  MOCK = "Mock",
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
}

function getDefaultValues(items: FormItem[]) {
  const data: Record<string, unknown> = {};
  items.forEach((item) => {
    data[item.id] = item.defaultValue;
  });
  return data;
}

function getStyles(name: string, selectItems: string[], theme: Theme) {
  return {
    fontWeight:
      selectItems.indexOf(name) === -1
        ? theme.typography.fontWeightRegular
        : theme.typography.fontWeightMedium,
  };
}

function FormProxyPluginField({
  category,
  value,
  id,
  onUpdate,
}: {
  value: string;
  category: string;
  id: string;
  onUpdate: (data: string) => void;
}) {
  const key = `${id}-${category}`;
  const arr: string[] = [];
  const fields: {
    label: string;
  }[] = [];
  const padding = " ";

  switch (category) {
    case ProxyPluginCategory.COMPRESSION: {
      arr.push(...value.split(padding));
      fields.push(
        {
          label: "Gzip Level",
        },
        {
          label: "Br Level",
        },
        {
          label: "Zstd Level",
        },
      );
      break;
    }
    case ProxyPluginCategory.ADMIN: {
      arr.push(...value.split(padding));
      fields.push(
        {
          label: "The basic auth",
        },
        {
          label: "The auth path",
        },
      );
      break;
    }
    case ProxyPluginCategory.LIMIT: {
      arr.push(...value.split(padding));
      fields.push(
        {
          label: "The limit key",
        },
        {
          label: "The limit value",
        },
      );
      break;
    }
    case ProxyPluginCategory.DIRECTORY: {
      arr.push(value);
      fields.push({
        label: "The static directory",
      });
      break;
    }
    case ProxyPluginCategory.MOCK: {
      break;
    }
    default: {
      arr.push(value);
      fields.push({
        label: "The stats path",
      });
      break;
    }
  }
  const [newValues, setNewValues] = React.useState(arr);

  const items = fields.map((item, index) => {
    return (
      <TextField
        key={`${key}-${index}`}
        id={`${key}-${index}`}
        label={item.label}
        variant="outlined"
        defaultValue={newValues[index] || ""}
        sx={{ ml: 1, flex: 1 }}
        style={{
          marginLeft: `${index * 15}px`,
        }}
        onChange={(e) => {
          const value = e.target.value.trim();
          const arr = newValues.slice(0);
          arr[index] = value;
          onUpdate(arr.join(padding));
          setNewValues(arr);
        }}
      />
    );
  });

  const list = (
    <Paper
      sx={{
        display: "flex",
        marginBottom: "15px",
        alignItems: "center",
        width: "100%",
      }}
    >
      {items}
    </Paper>
  );

  return <React.Fragment>{list}</React.Fragment>;
}

function FormSelectField({
  options,
  label,
  value,
  onUpdate,
}: {
  options?: string[];
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
        {opts.map((name) => (
          <MenuItem key={name} value={name}>
            {name}
          </MenuItem>
        ))}
      </Select>
    </React.Fragment>
  );
}

function FormTwoInputFields({
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
  const [newValues, setNewValues] = React.useState(arr);
  const divideToTwoValues = (value: string) => {
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
    if (name === undefined) {
      arr[1] = value || "";
    } else {
      arr[0] = name;
    }
    cloneValues[index] = arr.join(divide).trim();
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

export default function FormEditor({
  title,
  description,
  items,
  onUpsert,
  created,
  currentNames,
}: {
  title: string;
  description: string;
  items: FormItem[];
  onUpsert: (name: string, data: Record<string, unknown>) => Promise<void>;
  created?: boolean;
  currentNames?: string[];
}) {
  const theme = useTheme();
  const [data, setData] = React.useState(getDefaultValues(items));
  const defaultLocations: string[] = [];
  const defaultProxyPluginSelected: string[] = [];
  items.forEach((item) => {
    switch (item.category) {
      case FormItemCategory.LOCATION: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((lo) => {
          defaultLocations.push(lo);
        });
        break;
      }
      case FormItemCategory.PROXY_PLUGIN_SELECT: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((lo) => {
          defaultProxyPluginSelected.push(lo);
        });
        break;
      }
    }
  });

  const [locations, setLocations] = React.useState<string[]>(defaultLocations);
  const [selectedProxyPlugins, setSelectedProxyPlugins] = React.useState<
    string[]
  >(defaultProxyPluginSelected);

  const [updated, setUpdated] = React.useState(false);
  const [processing, setProcessing] = React.useState(false);
  const [showSuccess, setShowSuccess] = React.useState(false);
  const [newName, setNewName] = React.useState("");

  const [showError, setShowError] = React.useState({
    open: false,
    message: "",
  });

  const list = items.map((item) => {
    let formItem: JSX.Element = <></>;
    switch (item.category) {
      case FormItemCategory.CHECKBOX: {
        let options = (item.options as CheckBoxItem[]) || [];
        let defaultValue = 0;
        let labelItems = options.map((opt, index) => {
          if (item.defaultValue === opt.value) {
            defaultValue = opt.option;
          }
          return (
            <FormControlLabel
              key={item.id + "-label-" + index}
              value={opt.option}
              control={<Radio />}
              label={opt.label}
            />
          );
        });

        formItem = (
          <React.Fragment>
            <FormLabel id={item.id}>{item.label}</FormLabel>
            <RadioGroup
              row
              aria-labelledby={item.id}
              defaultValue={defaultValue}
              name="radio-buttons-group"
              onChange={(e) => {
                let value = Number(e.target.value);
                options.forEach((opt) => {
                  if (opt.option === value) {
                    updateValue(item.id, opt.value);
                  }
                });
              }}
            >
              {labelItems}
            </RadioGroup>
          </React.Fragment>
        );
        break;
      }
      case FormItemCategory.LOCATION: {
        const options = ((item.options as string[]) || []).sort();
        formItem = (
          <React.Fragment>
            <InputLabel id={`{item.id}-label`}>{item.label}</InputLabel>
            <Select
              labelId={`{item.id}-label`}
              id={item.label}
              multiple
              value={locations}
              onChange={(e) => {
                const values = (e.target.value as string[]).sort();
                setLocations(values);
                updateValue(item.id, values);
              }}
              input={<OutlinedInput label={item.label} />}
            >
              {options.map((name) => (
                <MenuItem
                  key={name}
                  value={name}
                  style={getStyles(name, locations, theme)}
                >
                  {name}
                </MenuItem>
              ))}
            </Select>
          </React.Fragment>
        );
        break;
      }
      case FormItemCategory.UPSTREAM:
      case FormItemCategory.WEBHOOK_TYPE: {
        formItem = (
          <FormSelectField
            label={item.label}
            options={item.options as string[]}
            value={(item.defaultValue as string) || ""}
            onUpdate={(value) => {
              updateValue(item.id, value);
            }}
          />
        );
        break;
      }
      case FormItemCategory.ADDRS: {
        formItem = (
          <FormTwoInputFields
            id={item.id}
            divide={" "}
            values={item.defaultValue as string[]}
            label={"Addr"}
            valueLabel={"Weight"}
            valueWidth="100px"
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
            addLabel="Add Address"
          />
        );
        break;
      }
      case FormItemCategory.HEADERS: {
        formItem = (
          <FormTwoInputFields
            id={item.id}
            divide={":"}
            values={item.defaultValue as string[]}
            label={"Header Name"}
            valueLabel={"Header Value"}
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
            addLabel="Add Response Header"
          />
        );
        break;
      }
      case FormItemCategory.PROXY_HEADERS: {
        formItem = (
          <FormTwoInputFields
            id={item.id}
            divide={":"}
            values={item.defaultValue as string[]}
            label={"Proxy Header Name"}
            valueLabel={"Proxy Header Value"}
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
            addLabel="Add Proxy Header"
          />
        );
        break;
      }
      case FormItemCategory.PROXY_PLUGIN: {
        const category = (data["category"] as string) || "";
        formItem = (
          <FormProxyPluginField
            key={`${item.id}-{category}`}
            value={(item.defaultValue as string) || ""}
            category={category}
            id={item.id}
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
          />
        );
        break;
      }
      case FormItemCategory.TEXTAREA: {
        let minRows = 4;
        if (item.minRows) {
          minRows = item.minRows;
        }
        formItem = (
          <TextField
            id={item.id}
            label={item.label}
            multiline
            minRows={minRows}
            variant="outlined"
            defaultValue={item.defaultValue}
            onChange={(e) => {
              updateValue(item.id, e.target.value.trim());
            }}
          />
        );
        break;
      }
      case FormItemCategory.PROXY_PLUGIN_SELECT: {
        const options = (item.options as CheckBoxItem[]) || [];
        const labelItems = options.map((opt, index) => {
          const value = opt.value as string;
          const checked = selectedProxyPlugins.includes(value);
          return (
            <FormControlLabel
              key={`${item.id}-${index}`}
              control={<Checkbox checked={checked} />}
              onChange={() => {
                if (!checked) {
                  const arr = selectedProxyPlugins.slice(0);
                  arr.push(value);
                  updateValue(item.id, arr);
                  setSelectedProxyPlugins(arr);
                } else {
                  const arr = selectedProxyPlugins
                    .slice(0)
                    .filter((item) => item !== value);
                  updateValue(item.id, arr);
                  setSelectedProxyPlugins(arr);
                }
              }}
              label={opt.label}
            />
          );
        });
        const selectedItems = selectedProxyPlugins.map((plugin, index) => {
          let action = <></>;
          if (index > 0) {
            action = (
              <IconButton
                edge="end"
                aria-label="delete"
                onClick={() => {
                  // ignore 0
                  if (index) {
                    const arr = selectedProxyPlugins.slice(0);
                    const value = arr[index];
                    arr[index] = arr[index - 1];
                    arr[index - 1] = value;
                    updateValue(item.id, arr);
                    setSelectedProxyPlugins(arr);
                  }
                }}
              >
                <KeyboardArrowUpIcon />
              </IconButton>
            );
          }
          return (
            <ListItem key={plugin} secondaryAction={action}>
              <ListItemText>{plugin}</ListItemText>
            </ListItem>
          );
        });
        formItem = (
          <React.Fragment>
            <Stack direction="row" spacing={2}>
              <Box
                style={{
                  width: "50%",
                }}
              >
                <FormLabel component="legend">Select proxy plugin</FormLabel>
                <FormGroup>{labelItems}</FormGroup>
              </Box>
              <Box>
                <FormLabel component="legend">
                  Sort selected proxy plugin
                </FormLabel>
                <FormGroup>
                  <List>{selectedItems}</List>
                </FormGroup>
              </Box>
            </Stack>
          </React.Fragment>
        );
        break;
      }
      default: {
        formItem = (
          <TextField
            id={item.id}
            label={item.label}
            variant="outlined"
            defaultValue={item.defaultValue || ""}
            onChange={(e) => {
              const value = e.target.value.trim();
              switch (item.category) {
                case FormItemCategory.NUMBER: {
                  if (value) {
                    updateValue(item.id, Number(value));
                  } else {
                    updateValue(item.id, null);
                  }
                  break;
                }
                default: {
                  updateValue(item.id, value);
                  break;
                }
              }
            }}
          />
        );
        break;
      }
    }
    return (
      <Grid item xs={item.span} key={item.id}>
        <FormControl fullWidth={true}>{formItem}</FormControl>
      </Grid>
    );
  });
  const updateValue = (key: string, value: unknown) => {
    setShowSuccess(false);
    const values = Object.assign({}, data);
    if (!value && typeof value == "string") {
      value = null;
    }
    values[key] = value;
    setUpdated(true);
    setData(values);
    setTimeout(() => {
      setShowSuccess(false);
    }, 6000);
  };
  const doUpsert = async () => {
    if (processing) {
      return;
    }
    setProcessing(true);
    try {
      if (created) {
        if (!newName) {
          throw new Error("Name is required");
        }
        if ((currentNames || []).includes(newName)) {
          throw new Error("Name is exists");
        }
      }
      await onUpsert(newName, data);
      setShowSuccess(true);
    } catch (err) {
      setShowError({
        open: true,
        message: formatError(err),
      });
    } finally {
      setProcessing(false);
    }
  };
  let createNewItem = <></>;
  if (created) {
    createNewItem = (
      <Grid item xs={12}>
        <FormControl fullWidth={true}>
          <TextField
            id={"new-item-name"}
            label={"Name"}
            variant="outlined"
            onChange={(e) => {
              setNewName(e.target.value.trim());
            }}
          />
        </FormControl>
      </Grid>
    );
  }
  return (
    <React.Fragment>
      <CardContent>
        <Typography
          sx={{ fontSize: 18, fontWeight: "bold" }}
          color="text.secondary"
          gutterBottom
        >
          {title}
        </Typography>
        <Typography variant="body1" gutterBottom mb={2}>
          {description}
        </Typography>
        <form noValidate autoComplete="off">
          <Grid container spacing={2}>
            {createNewItem}
            {list}
            <Grid item xs={12}>
              <Button
                disabled={!updated}
                fullWidth
                variant="outlined"
                size="large"
                onClick={() => {
                  doUpsert();
                }}
              >
                {processing ? "Submitting" : "Submit"}
              </Button>
            </Grid>
          </Grid>
        </form>
      </CardContent>
      {showSuccess && (
        <Alert
          style={{
            position: "fixed",
            right: "15px",
            bottom: "15px",
          }}
          icon={<CheckIcon fontSize="inherit" />}
          severity="success"
        >
          Update success!
        </Alert>
      )}
      <Snackbar
        open={showError.open}
        autoHideDuration={6000}
        onClose={() => {
          setShowError({
            open: false,
            message: "",
          });
        }}
        message={showError.message}
      />
    </React.Fragment>
  );
}
