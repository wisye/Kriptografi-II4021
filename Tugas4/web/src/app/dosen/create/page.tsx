import { Suspense } from "react";
import CreateForm from "./Create";

export default function CreatePage() {
    return (
        <Suspense
            fallback={
                <div className="text-white text-center">Loading form...</div>
            }
        >
            <CreateForm />
        </Suspense>
    );
}
