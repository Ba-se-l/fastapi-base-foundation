/**
 * Frontend Event Emitter
 * Enables decoupled communication between views, stores, and telemetry.
 */
class EventEmitter {
    constructor() {
        this.listeners = new Map();
    }

    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(callback);
        return () => this.off(event, callback);
    }

    off(event, callback) {
        if (this.listeners.has(event)) {
            this.listeners.get(event).delete(callback);
        }
    }

    emit(event, data) {
        if (this.listeners.has(event)) {
            // Snapshot listeners array to prevent infinite loops if listeners are added/removed during emit
            const snapshot = Array.from(this.listeners.get(event));
            snapshot.forEach(callback => {
                try {
                    callback(data);
                } catch (err) {
                    console.error(`Error in event listener for ${event}:`, err);
                }
            });
        }
    }
}

export const eventBus = new EventEmitter();
