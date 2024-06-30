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
import IconButton from "@mui/material/IconButton";
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
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import Divider from "@mui/material/Divider";
import { useTranslation } from "react-i18next";
import SubtitlesIcon from "@mui/icons-material/Subtitles";
import { useParams } from "react-router-dom";
import { useTheme } from "@mui/material/styles";
import { formatError } from "../helpers/util";
import {
  CheckBoxItem,
  FormItem,
  FormItemCategory,
  getStyles,
  getDefaultValues,
  FormSelectField,
  FormTwoInputFields,
} from "./form-common";
import { getPluginSteps, PluginCategory, FormPluginField } from "./form-plugin";

// TODO WEB管理界面流程后续优化，暂时仅保证可用
// 后续调整模块化
export default function FormEditor({
  title,
  description,
  items,
  onUpsert,
  onRemove,
  created,
  currentNames,
  hiddenIndex,
}: {
  title: string;
  description: string;
  items: FormItem[];
  onUpsert: (name: string, data: Record<string, unknown>) => Promise<void>;
  onRemove?: () => Promise<void>;
  created?: boolean;
  currentNames?: string[];
  hiddenIndex: number;
}) {
  const { name } = useParams();
  const { t } = useTranslation();
  const theme = useTheme();
  const [data, setData] = React.useState(getDefaultValues(items));
  const [showMore, setShowMore] = React.useState(false);
  const [openRemoveDialog, setOpenRemoveDialog] = React.useState(false);
  const [pluginCategory, setPluginCategory] = React.useState(
    (data["category"] as string) || "",
  );

  const defaultLocations: string[] = [];
  const defaultProxyPluginSelected: string[] = [];
  const defaultWebhookNotifications: string[] = [];
  items.forEach((item) => {
    switch (item.category) {
      case FormItemCategory.LOCATION: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((lo) => {
          defaultLocations.push(lo);
        });
        break;
      }
      case FormItemCategory.PLUGIN_SELECT: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((lo) => {
          defaultProxyPluginSelected.push(lo);
        });
        break;
      }
      case FormItemCategory.WEBHOOK_NOTIFICATIONS: {
        const arr = (item.defaultValue as string[]) || [];
        arr.forEach((item) => {
          defaultWebhookNotifications.push(item);
        });
        break;
      }
    }
  });

  const [locations, setLocations] = React.useState<string[]>(defaultLocations);
  const [selectedProxyPlugins, setSelectedProxyPlugins] = React.useState<
    string[]
  >(defaultProxyPluginSelected);
  const [webhookNotifications, setWebhookNotifications] = React.useState<
    string[]
  >(defaultWebhookNotifications);

  const [updated, setUpdated] = React.useState(false);
  const [processing, setProcessing] = React.useState(false);
  const [showSuccess, setShowSuccess] = React.useState(false);
  const [newName, setNewName] = React.useState("");

  const [showError, setShowError] = React.useState({
    open: false,
    message: "",
  });

  const showList: JSX.Element[] = [];
  const hideList: JSX.Element[] = [];

  items.map((item, index) => {
    let formItem: JSX.Element = <></>;
    switch (item.category) {
      case FormItemCategory.PLUGIN_STEP:
        // 复用后续流程
        item.options = getPluginSteps(pluginCategory || PluginCategory.STATS);
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
              disabled={item.disabled || false}
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
        const options = (item.options as string[]) || [];
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
      case FormItemCategory.WEBHOOK_NOTIFICATIONS: {
        const options = (item.options as string[]) || [];
        formItem = (
          <React.Fragment>
            <InputLabel id={`{item.id}-label`}>{item.label}</InputLabel>
            <Select
              labelId={`{item.id}-label`}
              id={item.label}
              multiple
              value={webhookNotifications}
              onChange={(e) => {
                const values = (e.target.value as string[]).sort();
                setWebhookNotifications(values);
                updateValue(item.id, values);
              }}
              input={<OutlinedInput label={item.label} />}
            >
              {options.map((name) => (
                <MenuItem
                  key={name}
                  value={name}
                  style={getStyles(name, webhookNotifications, theme)}
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
            label={t("form.addr")}
            valueLabel={t("form.weight")}
            valueWidth="100px"
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
            addLabel={t("form.addrs")}
          />
        );
        break;
      }
      case FormItemCategory.PROXY_SET_HEADERS: {
        formItem = (
          <FormTwoInputFields
            id={item.id}
            divide={":"}
            values={item.defaultValue as string[]}
            label={t("form.proxyHeaderName")}
            valueLabel={t("form.proxyHeaderValue")}
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
            addLabel={item.label}
          />
        );
        break;
      }
      case FormItemCategory.PROXY_ADD_HEADERS: {
        formItem = (
          <FormTwoInputFields
            id={item.id}
            divide={":"}
            values={item.defaultValue as string[]}
            label={t("form.proxyHeaderName")}
            valueLabel={t("form.proxyHeaderValue")}
            onUpdate={(data) => {
              updateValue(item.id, data);
            }}
            addLabel={item.label}
          />
        );
        break;
      }
      case FormItemCategory.PLUGIN: {
        const category = (data["category"] as string) || "";
        formItem = (
          <FormPluginField
            key={`${item.id}-{category}`}
            value={(item.defaultValue as Record<string, unknown>) || {}}
            category={category}
            id={item.id}
            onUpdate={(pluginData) => {
              const values = Object.assign({}, data, pluginData);
              updateRecord(values);
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
      case FormItemCategory.PLUGIN_SELECT: {
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
          const action = (
            <IconButton
              edge="end"
              aria-label="delete"
              disabled={index == 0}
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
          return (
            <ListItem key={plugin} secondaryAction={action} disablePadding>
              <ListItemText
                style={{
                  paddingRight: "50px",
                }}
              >
                {plugin}
              </ListItemText>
            </ListItem>
          );
        });
        let selectedBox = <></>;
        if (selectedItems.length !== 0) {
          selectedBox = (
            <Box>
              <FormLabel component="legend">{t("form.sortPlugin")}</FormLabel>
              <FormGroup>
                <List>{selectedItems}</List>
              </FormGroup>
            </Box>
          );
        }
        formItem = (
          <React.Fragment>
            <Stack direction="row" spacing={2}>
              <Box
                style={{
                  width: "50%",
                }}
              >
                <FormLabel component="legend">
                  {t("form.selectPlugin")}
                </FormLabel>
                <FormGroup>{labelItems}</FormGroup>
              </Box>
              {selectedBox}
            </Stack>
          </React.Fragment>
        );
        break;
      }
      default: {
        let defaultValue = item.defaultValue;
        if (defaultValue == null) {
          defaultValue = "";
        } else {
          defaultValue = `${defaultValue}`;
        }
        formItem = (
          <TextField
            id={item.id}
            label={item.label}
            variant="outlined"
            defaultValue={defaultValue}
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
    const grid = (
      <Grid item xs={12} sm={12} md={item.span} key={item.id}>
        <FormControl fullWidth={true}>{formItem}</FormControl>
      </Grid>
    );
    if (hiddenIndex != 0 && index > hiddenIndex) {
      hideList.push(grid);
    } else {
      showList.push(grid);
    }
  });
  const updateValue = (key: string, value: unknown) => {
    setShowSuccess(false);
    const values = Object.assign({}, data);
    if (!value && typeof value == "string") {
      value = null;
    }
    values[key] = value;
    updateRecord(values);
  };

  const updateRecord = (values: Record<string, unknown>) => {
    setUpdated(true);
    setData(values);
    setPluginCategory((values["category"] as string) || "");
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
          throw new Error(t("form.nameRequired"));
        }
        if ((currentNames || []).includes(newName)) {
          throw new Error(t("form.nameExists"));
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

  const doRemove = async () => {
    if (processing) {
      return;
    }
    setProcessing(true);
    try {
      setShowSuccess(true);
      if (onRemove) {
        await onRemove();
      }
    } catch (err) {
      setShowError({
        open: true,
        message: formatError(err),
      });
    } finally {
      setProcessing(false);
    }
  };
  let showRemove = false;
  if (onRemove) {
    showRemove = true;
  }
  let createNewItem = <></>;
  if (created) {
    showRemove = false;
    createNewItem = (
      <Grid item xs={12}>
        <FormControl fullWidth={true}>
          <TextField
            id={"new-item-name"}
            label={t("form.name")}
            variant="outlined"
            onChange={(e) => {
              setNewName(e.target.value.trim());
            }}
          />
        </FormControl>
      </Grid>
    );
  }
  let removeGrip = <></>;
  let submitSpan = 12;
  if (showRemove) {
    submitSpan = 8;
    removeGrip = (
      <Grid item xs={4}>
        <Button
          disabled={created}
          fullWidth
          variant="outlined"
          size="large"
          onClick={() => {
            setOpenRemoveDialog(true);
          }}
        >
          {processing ? t("form.removing") : t("form.remove")}
        </Button>
      </Grid>
    );
  }
  const handleCloseRemoveDialog = () => {
    setOpenRemoveDialog(false);
  };

  let nameFragment = <></>;
  if (name && name != "*") {
    nameFragment = (
      <h3
        style={{
          margin: "5px 0 15px 0",
          lineHeight: "24px",
        }}
      >
        <SubtitlesIcon
          style={{
            float: "left",
            marginRight: "5px",
          }}
        />
        <span>{name}</span>
      </h3>
    );
  }

  return (
    <React.Fragment>
      <CardContent>
        {nameFragment}
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
            {showList}
            {hideList.length != 0 && (
              <Grid item xs={12}>
                <Divider>
                  <Button
                    variant="text"
                    onClick={() => {
                      setShowMore(!showMore);
                    }}
                  >
                    {!showMore && t("form.showMore")}
                    {showMore && t("form.hideMore")}
                  </Button>
                </Divider>
              </Grid>
            )}
            {showMore && hideList}
            <Grid item xs={submitSpan}>
              <Button
                disabled={!updated}
                fullWidth
                variant="outlined"
                size="large"
                onClick={() => {
                  doUpsert();
                }}
              >
                {processing ? t("form.submitting") : t("form.submit")}
              </Button>
            </Grid>
            {removeGrip}
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
          {t("form.success")}
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
      <Dialog
        open={openRemoveDialog}
        onClose={handleCloseRemoveDialog}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">
          {t("form.confirmRemove")}
        </DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {t("form.removeDescript")}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseRemoveDialog}>{t("form.cancel")}</Button>
          <Button
            onClick={() => {
              doRemove();
              handleCloseRemoveDialog();
            }}
            autoFocus
          >
            {t("form.confirm")}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
}
