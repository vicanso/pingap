import * as React from "react";
import CardActions from "@mui/material/CardActions";
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

export enum FormItemCategory {
  TEXT = "text",
  NUMBER = "number",
  TEXTAREA = "textarea",
  CHECKBOX = "checkbox",
}

export interface FormItem {
  id: string;
  label: string;
  defaultValue: unknown;
  span: number;
  category: FormItemCategory;
}

export default function FormEditor({
  title,
  description,
  items,
  onUpdate,
}: {
  title: string;
  description: string;
  items: FormItem[];
  onUpdate: (data: Record<string, unknown>) => void;
}) {
  const data: Record<string, unknown> = {};
  const list = items.map((item) => {
    data[item.id] = item.defaultValue;
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
                data[item.id] = checked;
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
      case FormItemCategory.TEXTAREA: {
        formItem = (
          <TextField
            id={item.id}
            label={item.label}
            multiline
            minRows={4}
            variant="outlined"
            defaultValue={item.defaultValue}
            onChange={(e) => {
              data[item.id] = e.target.value.trim();
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
                    data[item.id] = Number(value);
                  } else {
                    data[item.id] = null;
                  }
                  break;
                }
                default: {
                  data[item.id] = value;
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
            {list}
          </Grid>
        </form>
      </CardContent>
      <CardActions>
        <Button size="small">Learn More</Button>
      </CardActions>
    </React.Fragment>
  );
}
