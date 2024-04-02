import * as React from "react";
import CardContent from "@mui/material/CardContent";
import Button from "@mui/material/Button";
import Typography from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import FormControl from "@mui/material/FormControl";
import Grid from "@mui/material/Grid";
import FormControlLabel from "@mui/material/FormControlLabel";
import RadioGroup from "@mui/material/RadioGroup";
import FormLabel from "@mui/material/FormLabel";
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
}

export interface FormItem {
  id: string;
  label: string;
  defaultValue: unknown;
  span: number;
  category: FormItemCategory;
  minRows?: number;
  options?: string[];
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
  const defaultAddrs: string[] = [];
  let defaultUpstream = "";
  items.forEach((item) => {
    switch (item.category) {
      case FormItemCategory.LOCATION: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((lo) => {
          defaultLocations.push(lo);
        });
        break;
      }
      case FormItemCategory.UPSTREAM: {
        defaultUpstream = item.defaultValue as string;
        break;
      }
      case FormItemCategory.ADDRS: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((addr) => {
          defaultAddrs.push(addr);
        });
        break;
      }
    }
  });

  const [locations, setLocations] = React.useState<string[]>(defaultLocations);
  const [upstream, setUpstream] = React.useState(defaultUpstream);
  const [addrs, setAddrs] = React.useState(defaultAddrs);

  const [updated, setUpdated] = React.useState(false);
  const [processing, setProcessing] = React.useState(false);
  const [showSuccess, setShowSuccess] = React.useState(false);
  const [newName, setNewName] = React.useState("");

  const [showError, setShowError] = React.useState({
    open: false,
    message: "",
  });

  const updateAddrAndWeight = (
    index: number,
    id: string,
    addr: string | undefined,
    weight: string | undefined,
  ) => {
    const values = addrs.slice(0);
    const arr = values[index].split(" ");
    // 更新weight
    if (addr === undefined) {
      arr[1] = weight || "";
    } else {
      arr[0] = addr;
    }
    const value = arr.join(" ").trim();
    values[index] = value;
    setAddrs(values);
    updateValue(id, values);
  };

  const list = items.map((item) => {
    let formItem: JSX.Element = <></>;
    switch (item.category) {
      case FormItemCategory.CHECKBOX: {
        let defaultValue = 0;
        if (item.defaultValue == null) {
          defaultValue = -1;
        } else if (item.defaultValue) {
          defaultValue = 1;
        }
        formItem = (
          <React.Fragment>
            <FormLabel id="demo-radio-buttons-group-label">
              {item.label}
            </FormLabel>
            <RadioGroup
              row
              aria-labelledby="demo-radio-buttons-group-label"
              defaultValue={defaultValue}
              name="radio-buttons-group"
              onChange={(e) => {
                let value = Number(e.target.value);
                let checked = null;
                switch (value) {
                  case 1: {
                    checked = true;
                    break;
                  }
                  case 0: {
                    checked = false;
                    break;
                  }
                  default: {
                    checked = null;
                    break;
                  }
                }
                updateValue(item.id, checked);
              }}
            >
              <FormControlLabel value={1} control={<Radio />} label="Yes" />
              <FormControlLabel value={0} control={<Radio />} label="No" />
              <FormControlLabel value={-1} control={<Radio />} label="None" />
            </RadioGroup>
          </React.Fragment>
        );
        break;
      }
      case FormItemCategory.LOCATION: {
        const options = item.options || [];
        formItem = (
          <React.Fragment>
            <InputLabel id={`{item.id}-label`}>{item.label}</InputLabel>
            <Select
              labelId={`{item.id}-label`}
              id={item.label}
              multiple
              value={locations}
              onChange={(e) => {
                const values = e.target.value as string[];
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
      case FormItemCategory.UPSTREAM: {
        const options = item.options || [];
        formItem = (
          <React.Fragment>
            <InputLabel id={`{item.id}-label`}>{item.label}</InputLabel>
            <Select
              labelId={`{item.id}-label`}
              id={item.label}
              value={upstream}
              onChange={(e) => {
                const { value } = e.target;
                setUpstream(value);
                updateValue(item.id, value);
              }}
              input={<OutlinedInput label={item.label} />}
            >
              {options.map((name) => (
                <MenuItem key={name} value={name}>
                  {name}
                </MenuItem>
              ))}
            </Select>
          </React.Fragment>
        );
        break;
      }
      case FormItemCategory.ADDRS: {
        const list = addrs.map((addrValue, index) => {
          const addrArr = addrValue.split(" ");
          const addr = addrArr[0];
          let weight = "";
          if (addrArr.length === 2) {
            weight = addrArr[1];
          }
          return (
            <Paper
              key={`${item.id}-${index}`}
              sx={{
                display: "flex",
                marginBottom: "15px",
                alignItems: "center",
                width: "100%",
              }}
            >
              <TextField
                id={`${item.id}-${index}`}
                label={item.label}
                variant="outlined"
                defaultValue={addr}
                sx={{ ml: 1, flex: 1 }}
                style={{
                  marginLeft: "0px",
                }}
                onChange={(e) => {
                  const value = e.target.value.trim();
                  updateAddrAndWeight(index, item.id, value, undefined);
                }}
              />
              <TextField
                id={`${item.id}-${index}-weight`}
                label={"Weight"}
                variant="outlined"
                defaultValue={weight}
                style={{
                  marginLeft: "10px",
                  width: "100px",
                }}
                onChange={(e) => {
                  const value = e.target.value.trim();
                  updateAddrAndWeight(index, item.id, undefined, value);
                }}
              />
              <IconButton
                color="primary"
                sx={{ p: "10px" }}
                aria-label="directions"
                onClick={() => {
                  const values = addrs.slice(0);
                  values.splice(index, 1);
                  setAddrs(values);
                  updateValue(item.id, values);
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
              const values = addrs.slice(0);
              values.push("");
              setAddrs(values);
              updateValue(item.id, values);
            }}
          >
            Add Address
          </Button>,
        );
        formItem = <React.Fragment>{list}</React.Fragment>;
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
      default: {
        formItem = (
          <TextField
            id={item.id}
            label={item.label}
            variant="outlined"
            defaultValue={item.defaultValue}
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
        <Alert icon={<CheckIcon fontSize="inherit" />} severity="success">
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
