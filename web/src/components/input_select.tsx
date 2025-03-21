import * as React from "react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { ExFormOption } from "@/constants";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";



interface InputSelectProps extends React.InputHTMLAttributes<HTMLInputElement> {
    defaultValue?: string;
    name: string;
    selectPlaceholder: string;
    inputPlaceholder: string;
    onValueChange: (values: string) => void;
    options: ExFormOption[] | undefined;
}

export const InputSelect = React.forwardRef<HTMLInputElement, InputSelectProps>(
    (
        {
            defaultValue = "",
            onValueChange,
            options,
            selectPlaceholder,
            inputPlaceholder,
            name,
            className,
            ...props
        },
        ref,
    ) => {
        let exists = options?.some((option) => option.value == defaultValue);
        if (!defaultValue) {
            exists = true;
        }
        const [isInputMode, setIsInputMode] = React.useState(!exists);
        let container = <Input type="text" value={defaultValue} onChange={(e) => {
            onValueChange(e.target.value);
        }} placeholder={inputPlaceholder} />;
        if (!isInputMode) {
            const items = options?.map((opt) => {
                return (
                    <SelectItem
                        key={`${name}-${opt.value}`}
                        value={opt.option}
                    >
                        {opt.label}
                    </SelectItem>
                );
            });
            container = <Select
                defaultValue={(defaultValue || "") as string}
                onValueChange={(option) => {
                    onValueChange(option);
                }}
            >
                <SelectTrigger>
                    <SelectValue placeholder={selectPlaceholder} />
                </SelectTrigger>
                <SelectContent>{items}</SelectContent>
            </Select>
        }

        return (
            <div className={cn(className, "flex")} ref={ref} {...props}>
                <div className="grow">
                    {container}
                </div>
                <div className="flex-none ml-2 mt-2">
                    <Switch checked={isInputMode} onCheckedChange={() => {
                        setIsInputMode(!isInputMode);
                    }} />
                </div>
            </div >
        );
    },
);

InputSelect.displayName = "InputSelect";