import { LoadingPage } from "@/components/loading";
import { useI18n } from "@/i18n";
import useConfigState, { Certificate } from "@/states/config";
import React from "react";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useEffect } from "react";
import { useShallow } from "zustand/react/shallow";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import History from "@/pages/History";

function getCertificateConfig(
  name: string,
  certificates?: Record<string, Certificate>,
) {
  if (!certificates) {
    return {} as Certificate;
  }
  return (certificates[name] || {}) as Certificate;
}

export default function Certificates() {
  const certificateI18n = useI18n("certificate");
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove, version] = useConfigState(
    useShallow((state) => [
      state.data,
      state.initialized,
      state.update,
      state.remove,
      state.version,
    ]),
  );
  const newCertificate = "*";
  const certificates = Object.keys(config.certificates || {});
  certificates.sort();
  certificates.unshift(newCertificate);
  const [currentCertificate, setCurrentCertificate] = React.useState(
    searchParams.get("name") || newCertificate,
  );
  useEffect(() => {
    setCurrentCertificate(searchParams.get("name") || newCertificate);
  }, [searchParams]);
  if (!initialized) {
    return <LoadingPage />;
  }

  const handleSelectCertificate = (name: string) => {
    setCurrentCertificate(name);
    if (name === newCertificate) {
      searchParams.delete("name");
    } else {
      searchParams.set("name", name);
    }
    setSearchParams(searchParams);
  };

  const certificateConfig = getCertificateConfig(
    currentCertificate,
    config.certificates,
  );
  const countLines = (value: string) => {
    const count = value.split("\n").length;
    return Math.min(Math.max(3, count), 8);
  };

  const items: ExFormItem[] = [
    {
      name: "tls_cert",
      label: certificateI18n("tlsCert"),
      placeholder: certificateI18n("tlsCertPlaceholder"),
      defaultValue: certificateConfig.tls_cert,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
      rows: countLines(certificateConfig.tls_cert || ""),
      nullAsEmpty: true,
    },
    {
      name: "tls_key",
      label: certificateI18n("tlsKey"),
      placeholder: certificateI18n("tlsKeyPlaceholder"),
      defaultValue: certificateConfig.tls_key,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
      rows: countLines(certificateConfig.tls_key || ""),
      nullAsEmpty: true,
    },
    {
      name: "domains",
      label: certificateI18n("domains"),
      placeholder: certificateI18n("domainsPlaceholder"),
      defaultValue: certificateConfig.domains,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "acme",
      label: certificateI18n("acme"),
      placeholder: "",
      defaultValue: certificateConfig.acme,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["lets_encrypt"], true, true),
    },
    {
      name: "is_default",
      label: certificateI18n("isDefault"),
      placeholder: "",
      defaultValue: certificateConfig.is_default,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "dns_challenge",
      label: certificateI18n("dnsChallenge"),
      placeholder: "",
      defaultValue: certificateConfig.dns_challenge,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "dns_provider",
      label: certificateI18n("dnsProvider"),
      placeholder: "",
      defaultValue: certificateConfig.dns_provider || "manual",
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(
        ["manual", "ali", "cf", "huawei", "tencent"],
        true,
        false,
      ),
    },
    {
      name: "dns_service_url",
      label: certificateI18n("dnsServiceUrl"),
      placeholder: certificateI18n("dnsServiceUrlPlaceholder"),
      defaultValue: certificateConfig.dns_service_url,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "is_ca",
      label: certificateI18n("isCa"),
      placeholder: "",
      defaultValue: certificateConfig.is_ca,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "buffer_days",
      label: certificateI18n("bufferDays"),
      placeholder: certificateI18n("bufferDaysPlaceholder"),
      defaultValue: certificateConfig.buffer_days,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
  ];

  let defaultShow = 2;
  if (currentCertificate === newCertificate) {
    defaultShow++;
    items.unshift({
      name: "name",
      label: certificateI18n("name"),
      placeholder: certificateI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }
  const schema = z.object({});
  const onRemove = async () => {
    return remove("certificate", currentCertificate).then(() => {
      handleSelectCertificate(newCertificate);
    });
  };

  const selectItems = certificates.map((certificate) => {
    let name = certificate;
    if (name === newCertificate) {
      name = "new";
    }
    return (
      <SelectItem key={certificate} value={certificate}>
        {name}
      </SelectItem>
    );
  });

  return (
    <div className="grow overflow-auto p-4">
      <div className="flex flex-row gap-2 mb-2">
        <Label>{certificateI18n("certificate")}:</Label>
        <Select
          value={currentCertificate}
          onValueChange={(value) => {
            if (value === newCertificate) {
              searchParams.delete("name");
            } else {
              searchParams.set("name", value);
            }
            setSearchParams(searchParams);
          }}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue
              placeholder={certificateI18n("certificatePlaceholder")}
            />
          </SelectTrigger>
          <SelectContent>{selectItems}</SelectContent>
        </Select>
      </div>
      <ExForm
        category="certificate"
        key={`${currentCertificate}-${version}`}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={currentCertificate === newCertificate ? undefined : onRemove}
        onSave={async (value) => {
          let name = currentCertificate;
          if (name === newCertificate) {
            name = value["name"] as string;
          }
          omitEmptyArrayString(value);
          await update("certificate", name, value);
          handleSelectCertificate(name);
        }}
      />
      {currentCertificate !== newCertificate && (
        <History
          category="certificate"
          name={currentCertificate}
          onRestore={async (data) => {
            await update("certificate", currentCertificate, data);
          }}
        />
      )}
    </div>
  );
}
