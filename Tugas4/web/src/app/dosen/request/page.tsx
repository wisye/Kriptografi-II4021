// page.tsx (Server Component by default)
import { Suspense } from "react";
import RequestShamir from "./Request";

export default function RequestPage() {
    return (
        <Suspense
            fallback={
                <div className="text-white text-center p-4">Loading...</div>
            }
        >
            <RequestShamir />
        </Suspense>
    );
}
