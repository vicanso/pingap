import CircularProgress from "@mui/material/CircularProgress";

export default function Loading() {
  return (
    <div
      style={{
        lineHeight: "40px",
        width: "140px",
        margin: "30px auto",
      }}
    >
      <CircularProgress
        style={{
          float: "left",
          marginRight: "10px",
        }}
      />
      Loading...
    </div>
  );
}
