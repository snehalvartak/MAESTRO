"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { LayerData, RiskLevel } from "@/lib/types";
import {
  AlertTriangle,
  Lightbulb,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  BookOpen,
} from "lucide-react";
import { Spinner } from "./icons";
import Markdown from "react-markdown";

interface LayerCardProps {
  layer: LayerData;
}

function getRiskBadgeClass(level: RiskLevel): string {
  switch (level) {
    case 'Critical':
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-300';
    case 'High':
      return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200 border-orange-300';
    case 'Medium':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-300';
    case 'Low':
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 border-green-300';
  }
}

export function LayerCard({ layer }: LayerCardProps) {
  const getStatusBadge = () => {
    switch (layer.status) {
      case "pending":
        return <Badge variant="secondary">Pending</Badge>;
      case "analyzing":
        return (
          <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
            <Spinner className="mr-1 h-3 w-3" />
            Analyzing...
          </Badge>
        );
      case "complete":
        return (
          <Badge className="bg-primary/20 text-primary-foreground dark:bg-primary/30 dark:text-primary-foreground">
            Complete
          </Badge>
        );
      case "error":
        return <Badge variant="destructive">Error</Badge>;
    }
  };

  return (
    <Card className="h-full flex flex-col">
      <CardHeader>
        <div className="flex justify-between items-start">
          <div>
            <CardTitle className="font-headline text-xl">{layer.name}</CardTitle>
            <CardDescription className="mt-1">
              MAESTRO Layer Analysis
            </CardDescription>
          </div>
          <div className="flex flex-col items-end gap-1">
            {getStatusBadge()}
            {layer.riskScore && (
              <Badge className={`text-xs border ${getRiskBadgeClass(layer.riskScore.riskLevel)}`}>
                Risk: {layer.riskScore.riskLevel}
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-grow flex flex-col">
        {layer.status === "analyzing" && (
          <div className="flex flex-col items-center justify-center flex-grow text-muted-foreground">
            <Spinner className="h-8 w-8 mb-2" />
            <p>AI is analyzing threats...</p>
          </div>
        )}

        {layer.status === "error" && (
           <div className="flex flex-col items-center justify-center flex-grow text-destructive">
             <XCircle className="h-8 w-8 mb-2" />
             <p>Analysis failed</p>
           </div>
        )}

        {layer.status === "complete" && layer.threat && layer.mitigation && (
          <Accordion type="single" collapsible defaultValue="item-1" className="w-full">
            <AccordionItem value="item-1">
              <AccordionTrigger className="font-semibold">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-destructive" />
                  Identified Threats
                </div>
              </AccordionTrigger>
              <AccordionContent className="text-muted-foreground prose prose-sm dark:prose-invert max-w-none">
                {layer.riskScore && (
                  <div className={`mb-3 p-2 rounded-md border text-xs ${getRiskBadgeClass(layer.riskScore.riskLevel)}`}>
                    <div className="flex gap-3 mb-1 font-semibold">
                      <span>Severity: {layer.riskScore.severity}</span>
                      <span>Likelihood: {layer.riskScore.likelihood}</span>
                      <span>Risk: {layer.riskScore.riskLevel}</span>
                    </div>
                    <p className="text-xs opacity-80">{layer.riskScore.rationale}</p>
                  </div>
                )}
                <Markdown>{layer.threat}</Markdown>
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="item-2">
              <AccordionTrigger className="font-semibold">
                 <div className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-primary" />
                  Mitigation Strategy
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-4">
                  <div>
                    <h4 className="font-semibold flex items-center gap-2 mb-1">
                      <ShieldCheck className="h-4 w-4 text-primary" />
                      Recommendation
                    </h4>
                    <p className="text-muted-foreground text-sm">
                      {layer.mitigation.recommendation}
                    </p>
                  </div>
                  <div>
                    <h4 className="font-semibold flex items-center gap-2 mb-1">
                      <Lightbulb className="h-4 w-4 text-yellow-500" />
                      Reasoning
                    </h4>
                    <p className="text-muted-foreground text-sm">
                      {layer.mitigation.reasoning}
                    </p>
                  </div>
                  <div>
                    <h4 className="font-semibold flex items-center gap-2 mb-1">
                      <AlertTriangle className="h-4 w-4 text-accent" />
                      Caveats
                    </h4>
                    <p className="text-muted-foreground text-sm">
                      {layer.mitigation.caveats}
                    </p>
                  </div>
                  {layer.mitigation.complianceMapping && (
                    <div>
                      <h4 className="font-semibold flex items-center gap-2 mb-2">
                        <BookOpen className="h-4 w-4 text-blue-500" />
                        Framework Mapping
                      </h4>
                      <div className="space-y-2 text-sm">
                        {layer.mitigation.complianceMapping.owaspAgenticAI.length > 0 && (
                          <div>
                            <span className="font-medium text-muted-foreground">OWASP Agentic AI: </span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {layer.mitigation.complianceMapping.owaspAgenticAI.map((ctrl) => (
                                <Badge key={ctrl} variant="outline" className="text-xs font-mono">
                                  {ctrl}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                        {layer.mitigation.complianceMapping.mitreAtlas.length > 0 && (
                          <div>
                            <span className="font-medium text-muted-foreground">MITRE ATLAS: </span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {layer.mitigation.complianceMapping.mitreAtlas.map((ctrl) => (
                                <Badge key={ctrl} variant="outline" className="text-xs font-mono">
                                  {ctrl}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        )}
      </CardContent>
    </Card>
  );
}
